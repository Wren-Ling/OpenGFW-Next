//go:build !linux

package io

import "errors"

type NFQueuePacketIOConfig struct {
	QueueSize      uint32
	QueueNum       *uint16
	Table          string
	ConnMarkAccept uint32
	ConnMarkDrop   uint32

	ReadBuffer  int
	WriteBuffer int
	Local       bool
	RST         bool
}

func NewNFQueuePacketIO(config NFQueuePacketIOConfig) (PacketIO, error) {
	return nil, errors.New("nfqueue io is only supported on linux")
}
