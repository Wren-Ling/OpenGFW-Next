//go:build linux

package io

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestAFPacketRingConfigValidation(t *testing.T) {
	pageSize := unix.Getpagesize()
	valid := AFPacketIOConfig{
		FrameSize:   2048,
		BlockSize:   pageSize,
		NumBlocks:   2,
		PollTimeout: time.Millisecond,
	}
	if pageSize%valid.FrameSize != 0 {
		valid.FrameSize = pageSize
	}
	if err := validateAFPacketRingConfig(valid); err != nil {
		t.Fatalf("validate valid ring config: %v", err)
	}

	tests := []struct {
		name    string
		config  AFPacketIOConfig
		wantErr string
	}{
		{
			name:    "unaligned block",
			config:  AFPacketIOConfig{FrameSize: 2048, BlockSize: pageSize + 1, NumBlocks: 1},
			wantErr: "multiple of page size",
		},
		{
			name:    "unaligned frame",
			config:  AFPacketIOConfig{FrameSize: 2049, BlockSize: pageSize, NumBlocks: 1},
			wantErr: "aligned",
		},
		{
			name:    "block not divisible by frame",
			config:  AFPacketIOConfig{FrameSize: 3072, BlockSize: pageSize, NumBlocks: 1},
			wantErr: "divisible",
		},
		{
			name:    "zero blocks",
			config:  AFPacketIOConfig{FrameSize: 2048, BlockSize: pageSize, NumBlocks: 0},
			wantErr: "positive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAFPacketRingConfig(tt.config)
			if err == nil {
				t.Fatal("validate succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestAFPacketRingConfigAdviceDefaults(t *testing.T) {
	advice, err := AFPacketRingConfigAdviceFor(AFPacketIOConfig{})
	if err != nil {
		t.Fatalf("AFPacketRingConfigAdviceFor(defaults) error = %v", err)
	}
	if advice.Config.FrameSize != afpacketDefaultRingFrameSize {
		t.Fatalf("default ring frameSize = %d, want %d", advice.Config.FrameSize, afpacketDefaultRingFrameSize)
	}
	if advice.Config.BlockSize != afpacketDefaultRingBlockSize {
		t.Fatalf("default ring blockSize = %d, want %d", advice.Config.BlockSize, afpacketDefaultRingBlockSize)
	}
	if advice.Config.NumBlocks != afpacketDefaultRingNumBlocks {
		t.Fatalf("default ring numBlocks = %d, want %d", advice.Config.NumBlocks, afpacketDefaultRingNumBlocks)
	}
	if advice.Config.PollTimeout != afpacketDefaultRingPollTimeout {
		t.Fatalf("default ring pollTimeout = %s, want %s", advice.Config.PollTimeout, afpacketDefaultRingPollTimeout)
	}
	if advice.FramesPerBlock != advice.Config.BlockSize/advice.Config.FrameSize {
		t.Fatalf("framesPerBlock = %d, want blockSize/frameSize", advice.FramesPerBlock)
	}
	if advice.FrameCount != advice.FramesPerBlock*advice.Config.NumBlocks {
		t.Fatalf("frameCount = %d, want framesPerBlock*numBlocks", advice.FrameCount)
	}
	if len(advice.Warnings) != 0 {
		t.Fatalf("default ring advice warnings = %v, want none", advice.Warnings)
	}
}

func TestAFPacketRingConfigAdviceWarnsForHighPPSUnfriendlySizing(t *testing.T) {
	advice, err := AFPacketRingConfigAdviceFor(AFPacketIOConfig{
		FrameSize:   65536,
		BlockSize:   1 << 20,
		NumBlocks:   1,
		PollTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("AFPacketRingConfigAdviceFor() error = %v", err)
	}
	joined := strings.Join(advice.Warnings, "\n")
	for _, want := range []string{"frames per block", "frameSize", "ring buffer", "retire_blk_tov"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings = %v, want substring %q", advice.Warnings, want)
		}
	}
}

func TestAFPacketRingProcessesBlockReleasesOwnershipAndCopiesPacket(t *testing.T) {
	blockSize := 4096
	block := make([]byte, blockSize)
	hdr := afpacketBlockHeader(block)
	hdr.Block_status = unix.TP_STATUS_USER
	hdr.Num_pkts = 1
	hdr.Offset_to_first_pkt = 128

	ethernet := testEthernetIPv4Packet()
	packetOffset := int(hdr.Offset_to_first_pkt)
	packetHdr := (*unix.Tpacket3Hdr)(unsafe.Pointer(&block[packetOffset]))
	packetHdr.Sec = 1710000000
	packetHdr.Nsec = 123
	packetHdr.Snaplen = uint32(len(ethernet))
	packetHdr.Len = uint32(len(ethernet))
	packetHdr.Mac = uint16(afpacketTPacketAlign(unix.SizeofTpacket3Hdr))
	copy(block[packetOffset+int(packetHdr.Mac):], ethernet)

	backend := &afPacketRingBackend{
		parent:    &afPacketIO{iface: "ogfw-test0"},
		ring:      block,
		blockSize: blockSize,
		numBlocks: 1,
	}
	blockIndex := 0
	var got Packet
	processed, keepGoing := backend.processAvailableBlocks(func(pkt Packet, err error) bool {
		if err != nil {
			t.Fatalf("callback error = %v", err)
		}
		got = pkt
		return true
	}, &blockIndex)
	if !processed || !keepGoing {
		t.Fatalf("processed/keepGoing = %v/%v, want true/true", processed, keepGoing)
	}
	if status := atomic.LoadUint32(&hdr.Block_status); status != unix.TP_STATUS_KERNEL {
		t.Fatalf("block status = %#x, want TP_STATUS_KERNEL", status)
	}
	if blockIndex != 0 {
		t.Fatalf("block index = %d, want 0 for single-block ring", blockIndex)
	}
	if got == nil {
		t.Fatal("callback packet = nil")
	}
	if got.Timestamp() != time.Unix(1710000000, 123) {
		t.Fatalf("timestamp = %v, want packet timestamp", got.Timestamp())
	}
	if meta := got.Metadata(); meta["capture.io"] != "afpacket" || meta["capture.interface"] != "ogfw-test0" {
		t.Fatalf("metadata = %#v, want afpacket capture metadata", meta)
	}
	payload := got.Data()
	if len(payload) < 20 || payload[0]>>4 != 4 {
		t.Fatalf("payload = %x, want IPv4 packet bytes", payload)
	}
	packetStart := packetOffset + int(packetHdr.Mac)
	block[packetStart+14] = 0
	if payload[0]>>4 != 4 {
		t.Fatal("packet data changed after ring memory mutation; want copied lifetime")
	}
}

func TestAFPacketRingCountsLosingBlocks(t *testing.T) {
	blockSize := 4096
	block := make([]byte, blockSize)
	hdr := afpacketBlockHeader(block)
	hdr.Block_status = unix.TP_STATUS_USER | unix.TP_STATUS_LOSING
	hdr.Num_pkts = 0
	hdr.Offset_to_first_pkt = 0

	backend := &afPacketRingBackend{
		parent:    &afPacketIO{iface: "ogfw-test0"},
		ring:      block,
		blockSize: blockSize,
		numBlocks: 1,
	}
	blockIndex := 0
	processed, keepGoing := backend.processAvailableBlocks(func(Packet, error) bool { return true }, &blockIndex)
	if !processed || !keepGoing {
		t.Fatalf("processed/keepGoing = %v/%v, want true/true", processed, keepGoing)
	}
	if got := backend.losingBlocks.Load(); got != 1 {
		t.Fatalf("losingBlocks = %d, want 1", got)
	}
}

func testEthernetIPv4Packet() []byte {
	return []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0x02,
		0x52, 0x54, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		192, 0, 2, 1,
		198, 51, 100, 2,
		0x12, 0x34, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
}
