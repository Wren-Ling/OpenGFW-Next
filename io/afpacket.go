//go:build linux

package io

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const (
	afpacketDefaultFrameSize       = 65536
	afpacketDefaultBlockSize       = 1 << 20
	afpacketDefaultNumBlocks       = 64
	afpacketDefaultPollTimeout     = 500 * time.Millisecond
	afpacketDefaultRingFrameSize   = 2048
	afpacketDefaultRingBlockSize   = 4 << 20
	afpacketDefaultRingNumBlocks   = 64
	afpacketDefaultRingPollTimeout = 50 * time.Millisecond
)

var _ PacketIO = (*afPacketIO)(nil)
var _ PacketIOStatsProvider = (*afPacketIO)(nil)

type afPacketIO struct {
	backend afPacketBackend
	dialer  *net.Dialer
	iface   string
}

type AFPacketIOConfig struct {
	Interface   string
	FrameSize   int
	BlockSize   int
	NumBlocks   int
	PollTimeout time.Duration
	Ring        bool
	FanoutGroup *uint16
	FanoutType  string
}

type afPacketBackend interface {
	Register(context.Context, PacketCallback) error
	Close() error
	Stats() PacketIOStats
}

type afPacketRawBackend struct {
	fd            int
	parent        *afPacketIO
	buffer        []byte
	kernelPackets atomic.Uint64
	kernelDrops   atomic.Uint64
	readErrors    atomic.Uint64
}

type afPacketRingBackend struct {
	fd            int
	parent        *afPacketIO
	ring          []byte
	blockSize     int
	numBlocks     int
	pollTimeoutMS int
	kernelPackets atomic.Uint64
	kernelDrops   atomic.Uint64
	losingBlocks  atomic.Uint64
	readErrors    atomic.Uint64
}

type AFPacketRingConfigAdvice struct {
	Config             AFPacketIOConfig
	FramesPerBlock     int
	FrameCount         int
	TotalBytes         int
	RetireBlockTimeout time.Duration
	Warnings           []string
}

func NewAFPacketPacketIO(config AFPacketIOConfig) (PacketIO, error) {
	if config.Interface == "" {
		return nil, errors.New("interface is required")
	}
	config = NormalizeAFPacketIOConfig(config)

	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return nil, err
	}
	fd, err := afpacketOpenSocket(config)
	if err != nil {
		return nil, err
	}

	a := &afPacketIO{
		dialer: &net.Dialer{},
		iface:  config.Interface,
	}
	if config.Ring {
		backend, err := newAFPacketRingBackend(fd, a, config)
		if err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		if err := afpacketBindAndConfigureSocket(fd, config, iface); err != nil {
			_ = backend.Close()
			return nil, err
		}
		a.backend = backend
	} else {
		if err := afpacketBindAndConfigureSocket(fd, config, iface); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		a.backend = &afPacketRawBackend{
			fd:     fd,
			parent: a,
			buffer: make([]byte, config.FrameSize),
		}
	}
	return a, nil
}

func (a *afPacketIO) Register(ctx context.Context, cb PacketCallback) error {
	return a.backend.Register(ctx, cb)
}

func (b *afPacketRawBackend) Register(ctx context.Context, cb PacketCallback) error {
	go func() {
		for {
			n, _, err := unix.Recvfrom(b.fd, b.buffer, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if afpacketShouldIgnoreReadError(err) {
					continue
				}
				b.readErrors.Add(1)
				if !cb(nil, err) {
					return
				}
				continue
			}
			if n == 0 {
				continue
			}

			data := b.buffer[:n]
			if !b.parent.deliverEthernetPacket(cb, data, time.Now()) {
				return
			}
		}
	}()

	return nil
}

func (b *afPacketRingBackend) Register(ctx context.Context, cb PacketCallback) error {
	go func() {
		blockIndex := 0
		for {
			if ctx.Err() != nil {
				return
			}
			processed, keepGoing := b.processAvailableBlocks(cb, &blockIndex)
			if !keepGoing {
				return
			}
			if processed {
				continue
			}
			if err := b.poll(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				if afpacketShouldIgnoreReadError(err) {
					continue
				}
				b.readErrors.Add(1)
				if !cb(nil, err) {
					return
				}
			}
		}
	}()

	return nil
}

func (a *afPacketIO) deliverEthernetPacket(cb PacketCallback, data []byte, timestamp time.Time) bool {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	payload := packetIPPayload(packet)
	if payload == nil {
		return true
	}
	return cb(&afPacket{
		streamID:  packetStreamID(packet),
		timestamp: timestamp,
		data:      payload,
		metadata:  a.metadata(packet),
	}, nil)
}

func (b *afPacketRingBackend) processAvailableBlocks(cb PacketCallback, blockIndex *int) (bool, bool) {
	processed := false
	for i := 0; i < b.numBlocks; i++ {
		idx := (*blockIndex + i) % b.numBlocks
		block := b.block(idx)
		hdr := afpacketBlockHeader(block)
		status := atomic.LoadUint32(&hdr.Block_status)
		if status&unix.TP_STATUS_USER == 0 {
			continue
		}
		if status&unix.TP_STATUS_LOSING != 0 {
			b.losingBlocks.Add(1)
		}
		processed = true
		if !b.processBlock(cb, block, hdr) {
			afpacketReleaseBlock(hdr)
			return true, false
		}
		afpacketReleaseBlock(hdr)
		*blockIndex = (idx + 1) % b.numBlocks
	}
	return processed, true
}

func (b *afPacketRingBackend) processBlock(cb PacketCallback, block []byte, hdr *unix.TpacketHdrV1) bool {
	offset := int(hdr.Offset_to_first_pkt)
	numPackets := int(hdr.Num_pkts)
	for i := 0; i < numPackets; i++ {
		if offset <= 0 || offset+unix.SizeofTpacket3Hdr > len(block) {
			b.readErrors.Add(1)
			return true
		}
		packetHdr := (*unix.Tpacket3Hdr)(unsafe.Pointer(&block[offset]))
		packetStart := offset + int(packetHdr.Mac)
		packetEnd := packetStart + int(packetHdr.Snaplen)
		if packetStart < offset || packetEnd < packetStart || packetEnd > len(block) {
			b.readErrors.Add(1)
			return true
		}

		data := make([]byte, packetHdr.Snaplen)
		copy(data, block[packetStart:packetEnd])
		timestamp := time.Unix(int64(packetHdr.Sec), int64(packetHdr.Nsec))
		if !b.parent.deliverEthernetPacket(cb, data, timestamp) {
			return false
		}

		if packetHdr.Next_offset == 0 {
			break
		}
		offset += int(packetHdr.Next_offset)
	}
	return true
}

func (b *afPacketRingBackend) poll(ctx context.Context) error {
	timeout := b.pollTimeoutMS
	if timeout <= 0 {
		timeout = int(afpacketDefaultPollTimeout / time.Millisecond)
	}
	for {
		_, err := unix.Poll([]unix.PollFd{{Fd: int32(b.fd), Events: unix.POLLIN | unix.POLLERR}}, timeout)
		if err == unix.EINTR {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		return err
	}
}

func afpacketShouldIgnoreReadError(err error) bool {
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return true
	}
	type timeout interface {
		Timeout() bool
	}
	if t, ok := err.(timeout); ok && t.Timeout() {
		return true
	}
	return false
}

func (a *afPacketIO) SetVerdict(pkt Packet, v Verdict, newPacket []byte) error {
	return nil
}

func (a *afPacketIO) Stats() PacketIOStats {
	if a == nil || a.backend == nil {
		return PacketIOStats{}
	}
	return a.backend.Stats()
}

func (a *afPacketIO) metadata(packet gopacket.Packet) PacketMetadata {
	m := packetMetadata(packet)
	if m == nil {
		m = make(PacketMetadata)
	}
	m["capture.io"] = "afpacket"
	m["capture.interface"] = a.iface
	return m
}

func (a *afPacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return a.dialer.DialContext(ctx, network, address)
}

func (a *afPacketIO) Close() error {
	return a.backend.Close()
}

func (a *afPacketIO) SetCancelFunc(cancelFunc context.CancelFunc) error {
	return nil
}

var _ Packet = (*afPacket)(nil)

type afPacket struct {
	streamID  uint32
	timestamp time.Time
	data      []byte
	metadata  PacketMetadata
}

func (p *afPacket) StreamID() uint32 {
	return p.streamID
}

func (p *afPacket) Timestamp() time.Time {
	return p.timestamp
}

func (p *afPacket) Data() []byte {
	return p.data
}

func (p *afPacket) Metadata() PacketMetadata {
	return p.metadata
}

func htons(i int) int {
	return (i<<8)&0xff00 | i>>8&0x00ff
}

func (b *afPacketRawBackend) Close() error {
	return unix.Close(b.fd)
}

func (b *afPacketRingBackend) Close() error {
	var err error
	if b.ring != nil {
		err = unix.Munmap(b.ring)
		b.ring = nil
	}
	if closeErr := unix.Close(b.fd); err == nil {
		err = closeErr
	}
	return err
}

func (b *afPacketRawBackend) Stats() PacketIOStats {
	packets, drops := afpacketSocketStats(b.fd, false)
	if packets > 0 {
		b.kernelPackets.Add(packets)
	}
	if drops > 0 {
		b.kernelDrops.Add(drops)
	}
	return PacketIOStats{
		Packets:    b.kernelPackets.Load(),
		Drops:      b.kernelDrops.Load(),
		ReadErrors: b.readErrors.Load(),
	}
}

func (b *afPacketRingBackend) Stats() PacketIOStats {
	packets, drops := afpacketSocketStats(b.fd, true)
	if packets > 0 {
		b.kernelPackets.Add(packets)
	}
	if drops > 0 {
		b.kernelDrops.Add(drops)
	}
	return PacketIOStats{
		Packets:          b.kernelPackets.Load(),
		Drops:            b.kernelDrops.Load(),
		ReadErrors:       b.readErrors.Load(),
		RingLosingBlocks: b.losingBlocks.Load(),
	}
}

func afpacketSocketStats(fd int, v3 bool) (uint64, uint64) {
	if v3 {
		if kernelStats, err := unix.GetsockoptTpacketStatsV3(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil && kernelStats != nil {
			return uint64(kernelStats.Packets), uint64(kernelStats.Drops)
		}
		return 0, 0
	}
	if kernelStats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil && kernelStats != nil {
		return uint64(kernelStats.Packets), uint64(kernelStats.Drops)
	}
	return 0, 0
}

func afpacketOpenSocket(config AFPacketIOConfig) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(unix.ETH_P_ALL))
	if err != nil {
		return -1, err
	}
	if config.Ring {
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("set afpacket tpacket version: %w", err)
		}
	}
	return fd, nil
}

func afpacketBindAndConfigureSocket(fd int, config AFPacketIOConfig, iface *net.Interface) error {
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: uint16(htons(unix.ETH_P_ALL)),
		Ifindex:  iface.Index,
	}); err != nil {
		return err
	}
	if config.FanoutGroup != nil {
		fanoutType, err := afpacketFanoutType(config.FanoutType)
		if err != nil {
			return err
		}
		fanoutArg := int(*config.FanoutGroup) | (fanoutType << 16)
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
			return fmt.Errorf("set afpacket fanout: %w", err)
		}
	}
	if !config.Ring && config.BlockSize > 0 && config.NumBlocks > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, config.BlockSize*config.NumBlocks)
	}
	if !config.Ring && config.PollTimeout > 0 {
		tv := unix.NsecToTimeval(config.PollTimeout.Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	}
	return nil
}

func newAFPacketRingBackend(fd int, parent *afPacketIO, config AFPacketIOConfig) (*afPacketRingBackend, error) {
	if err := validateAFPacketRingConfig(config); err != nil {
		return nil, err
	}
	frameNr := config.NumBlocks * (config.BlockSize / config.FrameSize)
	req := &unix.TpacketReq3{
		Block_size:     uint32(config.BlockSize),
		Block_nr:       uint32(config.NumBlocks),
		Frame_size:     uint32(config.FrameSize),
		Frame_nr:       uint32(frameNr),
		Retire_blk_tov: uint32(config.PollTimeout / time.Millisecond),
	}
	if req.Retire_blk_tov == 0 {
		req.Retire_blk_tov = uint32(afpacketDefaultPollTimeout / time.Millisecond)
	}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, req); err != nil {
		return nil, fmt.Errorf("set afpacket rx ring: %w", err)
	}
	ring, err := unix.Mmap(fd, 0, config.BlockSize*config.NumBlocks, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap afpacket rx ring: %w", err)
	}
	return &afPacketRingBackend{
		fd:            fd,
		parent:        parent,
		ring:          ring,
		blockSize:     config.BlockSize,
		numBlocks:     config.NumBlocks,
		pollTimeoutMS: int(config.PollTimeout / time.Millisecond),
	}, nil
}

func NormalizeAFPacketIOConfig(config AFPacketIOConfig) AFPacketIOConfig {
	if config.Ring {
		if config.FrameSize <= 0 {
			config.FrameSize = afpacketDefaultRingFrameSize
		}
		if config.BlockSize <= 0 {
			config.BlockSize = afpacketDefaultRingBlockSize
		}
		if config.NumBlocks <= 0 {
			config.NumBlocks = afpacketDefaultRingNumBlocks
		}
		if config.PollTimeout <= 0 {
			config.PollTimeout = afpacketDefaultRingPollTimeout
		}
		return config
	}
	if config.FrameSize <= 0 {
		config.FrameSize = afpacketDefaultFrameSize
	}
	if config.BlockSize <= 0 {
		config.BlockSize = afpacketDefaultBlockSize
	}
	if config.NumBlocks <= 0 {
		config.NumBlocks = afpacketDefaultNumBlocks
	}
	if config.PollTimeout <= 0 {
		config.PollTimeout = afpacketDefaultPollTimeout
	}
	return config
}

func AFPacketRingConfigAdviceFor(config AFPacketIOConfig) (AFPacketRingConfigAdvice, error) {
	config.Ring = true
	config = NormalizeAFPacketIOConfig(config)
	if err := validateAFPacketRingConfig(config); err != nil {
		return AFPacketRingConfigAdvice{}, err
	}
	framesPerBlock := config.BlockSize / config.FrameSize
	frameCount := config.NumBlocks * framesPerBlock
	advice := AFPacketRingConfigAdvice{
		Config:             config,
		FramesPerBlock:     framesPerBlock,
		FrameCount:         frameCount,
		TotalBytes:         config.BlockSize * config.NumBlocks,
		RetireBlockTimeout: config.PollTimeout,
	}
	if framesPerBlock < 64 {
		advice.Warnings = append(advice.Warnings, fmt.Sprintf("frames per block is %d; use a larger blockSize or smaller frameSize for high PPS capture", framesPerBlock))
	}
	if config.FrameSize > 4096 {
		advice.Warnings = append(advice.Warnings, fmt.Sprintf("frameSize is %d; 2048 or 4096 is usually better for high PPS non-jumbo traffic", config.FrameSize))
	}
	if advice.TotalBytes < 128<<20 {
		advice.Warnings = append(advice.Warnings, fmt.Sprintf("ring buffer is %d MiB; consider at least 128 MiB for bursty high PPS mirrors", advice.TotalBytes>>20))
	}
	if config.PollTimeout > 100*time.Millisecond {
		advice.Warnings = append(advice.Warnings, fmt.Sprintf("retire_blk_tov is %s; 10-50ms usually lowers latency and block pressure under high PPS", config.PollTimeout))
	}
	if config.PollTimeout < time.Millisecond {
		advice.Warnings = append(advice.Warnings, fmt.Sprintf("retire_blk_tov is %s; very small values increase wakeups and CPU overhead", config.PollTimeout))
	}
	return advice, nil
}

func validateAFPacketRingConfig(config AFPacketIOConfig) error {
	pageSize := unix.Getpagesize()
	if config.BlockSize <= 0 || config.FrameSize <= 0 || config.NumBlocks <= 0 {
		return errors.New("afpacket ring requires positive blockSize, frameSize, and numBlocks")
	}
	if config.BlockSize%pageSize != 0 {
		return fmt.Errorf("afpacket ring blockSize %d must be a multiple of page size %d", config.BlockSize, pageSize)
	}
	if config.FrameSize%afpacketTPacketAlignment != 0 {
		return fmt.Errorf("afpacket ring frameSize %d must be %d-byte aligned", config.FrameSize, afpacketTPacketAlignment)
	}
	if config.FrameSize < afpacketTPacketAlign(unix.SizeofTpacket3Hdr) {
		return fmt.Errorf("afpacket ring frameSize %d is smaller than tpacket3 header size %d", config.FrameSize, unix.SizeofTpacket3Hdr)
	}
	if config.BlockSize%config.FrameSize != 0 {
		return fmt.Errorf("afpacket ring blockSize %d must be divisible by frameSize %d", config.BlockSize, config.FrameSize)
	}
	if config.NumBlocks > int(^uint32(0)) || config.BlockSize > int(^uint32(0)) || config.FrameSize > int(^uint32(0)) {
		return errors.New("afpacket ring sizes exceed kernel uint32 limits")
	}
	frameNr := uint64(config.NumBlocks) * uint64(config.BlockSize/config.FrameSize)
	if frameNr == 0 || frameNr > uint64(^uint32(0)) {
		return errors.New("afpacket ring frame count exceeds kernel uint32 limits")
	}
	return nil
}

func (b *afPacketRingBackend) block(index int) []byte {
	start := index * b.blockSize
	return b.ring[start : start+b.blockSize]
}

func afpacketBlockHeader(block []byte) *unix.TpacketHdrV1 {
	desc := (*unix.TpacketBlockDesc)(unsafe.Pointer(&block[0]))
	return (*unix.TpacketHdrV1)(unsafe.Pointer(&desc.Hdr[0]))
}

func afpacketReleaseBlock(hdr *unix.TpacketHdrV1) {
	atomic.StoreUint32(&hdr.Block_status, unix.TP_STATUS_KERNEL)
}

const afpacketTPacketAlignment = 16

func afpacketTPacketAlign(value int) int {
	return (value + afpacketTPacketAlignment - 1) &^ (afpacketTPacketAlignment - 1)
}

func afpacketFanoutType(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "hash":
		return unix.PACKET_FANOUT_HASH, nil
	case "lb", "loadbalance", "load-balance":
		return unix.PACKET_FANOUT_LB, nil
	case "cpu":
		return unix.PACKET_FANOUT_CPU, nil
	case "rollover":
		return unix.PACKET_FANOUT_ROLLOVER, nil
	case "rnd", "random":
		return unix.PACKET_FANOUT_RND, nil
	case "qm", "queue-mapping":
		return unix.PACKET_FANOUT_QM, nil
	default:
		return 0, fmt.Errorf("unsupported afpacket fanout type %q", value)
	}
}
