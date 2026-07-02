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
