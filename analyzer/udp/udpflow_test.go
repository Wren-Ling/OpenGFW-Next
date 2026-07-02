package udp

import (
	"testing"
	"time"

	"github.com/apernet/OpenGFW/analyzer"
)

func TestUDPFlowStreamStats(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	s := &udpFlowStream{
		srcPort: 53000,
		dstPort: 443,
		now: func() time.Time {
			return now
		},
	}

	u, done := s.Feed(false, make([]byte, 100))
	if done {
		t.Fatal("Feed() done = true, want false")
	}
	assertUDPFlowProps(t, u.M, analyzer.PropMap{
		"src_port":                uint16(53000),
		"dst_port":                uint16(443),
		"packet_count":            1,
		"tx_packet_count":         1,
		"rx_packet_count":         0,
		"tx_packet_ratio":         1.0,
		"rx_packet_ratio":         0.0,
		"first_packet_len":        100,
		"second_packet_len":       0,
		"first_tx_packet_len":     100,
		"first_rx_packet_len":     0,
		"min_packet_len":          100,
		"max_packet_len":          100,
		"avg_packet_len":          100.0,
		"tx_bytes":                100,
		"rx_bytes":                0,
		"total_bytes":             100,
		"tx_byte_ratio":           1.0,
		"rx_byte_ratio":           0.0,
		"duration_seconds":        0.0,
		"packet_rate":             0.0,
		"byte_rate":               0.0,
		"long_lived":              false,
		"bidirectional":           false,
		"large_packet_count":      0,
		"large_packet_ratio":      0.0,
		"small_packet_count":      1,
		"small_packet_ratio":      1.0,
		"direction_change_count":  0,
		"max_same_direction_run":  1,
		"tx_dominant":             true,
		"rx_dominant":             false,
		"balanced_directions":     false,
		"len_bucket_le128_count":  1,
		"len_bucket_le128_ratio":  1.0,
		"len_bucket_gt1200_count": 0,
		"len_bucket_gt1200_ratio": 0.0,
		"udp443":                  true,
	})

	now = now.Add(udpFlowLongLivedThreshold + time.Second)
	u, done = s.Feed(true, make([]byte, 300))
	if done {
		t.Fatal("Feed() done = true, want false")
	}
	assertUDPFlowProps(t, u.M, analyzer.PropMap{
		"src_port":               uint16(53000),
		"dst_port":               uint16(443),
		"packet_count":           2,
		"tx_packet_count":        1,
		"rx_packet_count":        1,
		"tx_packet_ratio":        0.5,
		"rx_packet_ratio":        0.5,
		"first_packet_len":       100,
		"second_packet_len":      300,
		"first_tx_packet_len":    100,
		"first_rx_packet_len":    300,
		"min_packet_len":         100,
		"max_packet_len":         300,
		"avg_packet_len":         200.0,
		"tx_bytes":               100,
		"rx_bytes":               300,
		"total_bytes":            400,
		"tx_byte_ratio":          0.25,
		"rx_byte_ratio":          0.75,
		"duration_seconds":       (udpFlowLongLivedThreshold + time.Second).Seconds(),
		"long_lived":             true,
		"bidirectional":          true,
		"large_packet_count":     0,
		"large_packet_ratio":     0.0,
		"small_packet_count":     1,
		"small_packet_ratio":     0.5,
		"direction_change_count": 1,
		"max_same_direction_run": 1,
		"tx_dominant":            false,
		"rx_dominant":            false,
		"balanced_directions":    true,
		"len_bucket_le128_count": 1,
		"len_bucket_le128_ratio": 0.5,
		"len_bucket_le512_count": 1,
		"len_bucket_le512_ratio": 0.5,
		"udp443":                 true,
	})
	if s.lenBuckets[udpFlowLenBucket(100)] != 1 {
		t.Fatalf("100 byte bucket count = %d, want 1", s.lenBuckets[udpFlowLenBucket(100)])
	}
	if s.lenBuckets[udpFlowLenBucket(300)] != 1 {
		t.Fatalf("300 byte bucket count = %d, want 1", s.lenBuckets[udpFlowLenBucket(300)])
	}
}

func TestUDPFlowAnalyzerDstPort(t *testing.T) {
	a := &UDPFlowAnalyzer{}
	if a.Name() != "udpflow" {
		t.Fatalf("Name() = %q, want udpflow", a.Name())
	}
	if a.Limit() != 0 {
		t.Fatalf("Limit() = %d, want 0", a.Limit())
	}

	stream := a.NewUDP(analyzer.UDPInfo{DstPort: 8443}, nil)
	u, done := stream.Feed(false, []byte("hello"))
	if done {
		t.Fatal("Feed() done = true, want false")
	}
	if got := u.M["udp443"]; got != false {
		t.Fatalf("udp443 = %v, want false", got)
	}
}

func assertUDPFlowProps(t *testing.T, got, want analyzer.PropMap) {
	t.Helper()
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("%s = %#v, want %#v; all props: %#v", key, got[key], wantValue, got)
		}
	}
}
