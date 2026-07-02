//go:build !linux

package io

import (
	"errors"
	"time"
)

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

func NewAFPacketPacketIO(config AFPacketIOConfig) (PacketIO, error) {
	return nil, errors.New("afpacket io is only supported on linux")
}
