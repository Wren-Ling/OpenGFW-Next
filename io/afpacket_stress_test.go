package io

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestAFPacketRingBackendLocalStress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("afpacket ring stress test requires linux")
	}
	iface := os.Getenv("OPENGFW_AFPACKET_STRESS_IFACE")
	if iface == "" {
		t.Skip("set OPENGFW_AFPACKET_STRESS_IFACE to run the local TPACKET_V3 stress test")
	}

	config := AFPacketIOConfig{
		Interface:   iface,
		Ring:        true,
		FrameSize:   envInt("OPENGFW_AFPACKET_STRESS_FRAME_SIZE", 0),
		BlockSize:   envInt("OPENGFW_AFPACKET_STRESS_BLOCK_SIZE", 0),
		NumBlocks:   envInt("OPENGFW_AFPACKET_STRESS_NUM_BLOCKS", 0),
		PollTimeout: envDuration("OPENGFW_AFPACKET_STRESS_RETIRE_BLK_TOV", 0),
	}
	advice, err := AFPacketRingConfigAdviceFor(config)
	if err != nil {
		t.Fatalf("ring config advice: %v", err)
	}
	for _, warning := range advice.Warnings {
		t.Logf("ring sizing recommendation: %s", warning)
	}

	packetIO, err := NewAFPacketPacketIO(advice.Config)
	if err != nil {
		t.Fatalf("NewAFPacketPacketIO: %v", err)
	}
	defer packetIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var callbacks atomic.Uint64
	var callbackErrors atomic.Uint64
	if err := packetIO.Register(ctx, func(pkt Packet, err error) bool {
		if err != nil {
			callbackErrors.Add(1)
			return true
		}
		if pkt != nil {
			callbacks.Add(1)
		}
		return true
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	duration := envDuration("OPENGFW_AFPACKET_STRESS_DURATION", 10*time.Second)
	t.Logf("capturing iface=%s duration=%s frameSize=%d blockSize=%d numBlocks=%d retire_blk_tov=%s",
		iface, duration, advice.Config.FrameSize, advice.Config.BlockSize, advice.Config.NumBlocks, advice.Config.PollTimeout)
	time.Sleep(duration)
	cancel()
	statsProvider := packetIO.(PacketIOStatsProvider)
	stats := statsProvider.Stats()
	dropRate := PacketIODropRate(stats.Packets, stats.Drops)
	t.Logf("callbacks=%d callbackErrors=%d kernelPackets=%d kernelDrops=%d dropRate=%.6f ringLosingBlocks=%d readErrors=%d",
		callbacks.Load(), callbackErrors.Load(), stats.Packets, stats.Drops, dropRate, stats.RingLosingBlocks, stats.ReadErrors)

	maxDropRate := envFloat("OPENGFW_AFPACKET_STRESS_MAX_DROP_RATE", 0.01)
	if dropRate > maxDropRate || stats.RingLosingBlocks > 0 {
		t.Fatalf("drop rate %.6f or losing blocks %d exceeded threshold %.6f", dropRate, stats.RingLosingBlocks, maxDropRate)
	}
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloat(key string, fallback float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
