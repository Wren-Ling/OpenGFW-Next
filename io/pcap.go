package io

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

var _ PacketIO = (*pcapPacketIO)(nil)

type pcapPacketIO struct {
	pcapFile   io.ReadCloser
	pcap       *pcapgo.Reader
	timeOffset *time.Duration
	ioCancel   context.CancelFunc
	config     PcapPacketIOConfig

	dialer *net.Dialer
}

type PcapPacketIOConfig struct {
	PcapFile string
	Realtime bool
}

func NewPcapPacketIO(config PcapPacketIOConfig) (PacketIO, error) {
	pcapFile, err := os.Open(config.PcapFile)
	if err != nil {
		return nil, err
	}

	handle, err := pcapgo.NewReader(pcapFile)
	if err != nil {
		return nil, err
	}

	return &pcapPacketIO{
		pcapFile:   pcapFile,
		pcap:       handle,
		timeOffset: nil,
		ioCancel:   nil,
		config:     config,
		dialer:     &net.Dialer{},
	}, nil
}

func (p *pcapPacketIO) Register(ctx context.Context, cb PacketCallback) error {
	go func() {
		packetSource := gopacket.NewPacketSource(p.pcap, p.pcap.LinkType())
		for packet := range packetSource.Packets() {
			p.wait(packet)

			payload := packetIPPayload(packet)
			if payload != nil {
				cb(&pcapPacket{
					streamID:  packetStreamID(packet),
					timestamp: packet.Metadata().Timestamp,
					data:      payload,
					metadata:  p.metadata(packet),
				}, nil)
			}
		}
		// Give the workers a chance to finish everything
		time.Sleep(time.Second)
		// Stop the engine when all packets are finished
		p.ioCancel()
	}()

	return nil
}

// A normal dialer is sufficient as pcap IO does not mess up with the networking
func (p *pcapPacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return p.dialer.DialContext(ctx, network, address)
}

func (p *pcapPacketIO) SetVerdict(pkt Packet, v Verdict, newPacket []byte) error {
	return nil
}

func (p *pcapPacketIO) metadata(packet gopacket.Packet) PacketMetadata {
	m := packetMetadata(packet)
	if m == nil {
		m = make(PacketMetadata)
	}
	m["capture.io"] = "pcap"
	return m
}

func (p *pcapPacketIO) SetCancelFunc(cancelFunc context.CancelFunc) error {
	p.ioCancel = cancelFunc
	return nil
}

func (p *pcapPacketIO) Close() error {
	return p.pcapFile.Close()
}

// Intentionally slow down the replay
// In realtime mode, this is to match the timestamps in the capture
func (p *pcapPacketIO) wait(packet gopacket.Packet) {
	if !p.config.Realtime {
		return
	}

	if p.timeOffset == nil {
		offset := time.Since(packet.Metadata().Timestamp)
		p.timeOffset = &offset
	} else {
		t := time.Until(packet.Metadata().Timestamp.Add(*p.timeOffset))
		time.Sleep(t)
	}
}

var _ Packet = (*pcapPacket)(nil)

type pcapPacket struct {
	streamID  uint32
	timestamp time.Time
	data      []byte
	metadata  PacketMetadata
}

func (p *pcapPacket) StreamID() uint32 {
	return p.streamID
}

func (p *pcapPacket) Timestamp() time.Time {
	return p.timestamp
}

func (p *pcapPacket) Data() []byte {
	return p.data
}

func (p *pcapPacket) Metadata() PacketMetadata {
	return p.metadata
}
