package io

import "testing"

func TestPacketIODropRate(t *testing.T) {
	if got := PacketIODropRate(0, 0); got != 0 {
		t.Fatalf("PacketIODropRate(0, 0) = %v, want 0", got)
	}
	if got, want := PacketIODropRate(90, 10), 0.1; got != want {
		t.Fatalf("PacketIODropRate(90, 10) = %v, want %v", got, want)
	}
}
