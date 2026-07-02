//go:build !linux

package io

import (
	"strings"
	"testing"
)

func TestAFPacketStubRejectsNonLinux(t *testing.T) {
	_, err := NewAFPacketPacketIO(AFPacketIOConfig{
		Interface: "ogfw-mon0",
		Ring:      true,
	})
	if err == nil {
		t.Fatal("NewAFPacketPacketIO() error = nil, want non-linux error")
	}
	if !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("error = %v, want non-linux message", err)
	}
}
