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

type AFPacketRingConfigAdvice struct {
	Config             AFPacketIOConfig
	FramesPerBlock     int
	FrameCount         int
	TotalBytes         int
	RetireBlockTimeout time.Duration
	Warnings           []string
}

func NewAFPacketPacketIO(config AFPacketIOConfig) (PacketIO, error) {
	return nil, errors.New("afpacket io is only supported on linux")
}

func NormalizeAFPacketIOConfig(config AFPacketIOConfig) AFPacketIOConfig {
	return config
}

func AFPacketRingConfigAdviceFor(config AFPacketIOConfig) (AFPacketRingConfigAdvice, error) {
	return AFPacketRingConfigAdvice{}, errors.New("afpacket io is only supported on linux")
}
