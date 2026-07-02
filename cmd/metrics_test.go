package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	opengfwio "github.com/apernet/OpenGFW/io"
)

func TestMetricsCollectorRender(t *testing.T) {
	m := &metricsCollector{}
	m.IncRuleHit("vpn-wireguard", "high")
	m.IncRuleHit("vpn-wireguard", "high")
	m.IncRuleHit("quote\"rule", "line\nseverity")
	m.IncAlertDropped()
	m.IncAllowlistSuppressed("domain\"reason\nline")
	m.IncResponseApplied("ovs")
	m.IncResponseFailed("ovs")
	m.IncStream("udp")
	m.IncStream("tcp")
	m.IncStream("udp")
	m.IncRiskEvent("high\"risk\nline")
	m.packetIO = fakePacketStatsProvider{stats: opengfwio.PacketIOStats{
		Packets:    100,
		Drops:      7,
		ReadErrors: 2,
	}}
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	m.SetRiskAggregator(&riskAggregator{
		window: 10 * time.Minute,
		now:    func() time.Time { return now },
		buckets: map[string]*riskBucket{
			"vm.id\x00vm-100": {
				Key:     "vm-100",
				KeyType: "vm.id",
				Hits: []riskHit{{
					Time:   now,
					Rule:   "vpn-wireguard",
					Weight: 6,
				}},
				Score: 6,
			},
		},
	})

	out := m.Render()
	for _, want := range []string{
		"# TYPE opengfw_rule_hits_total counter",
		"opengfw_rule_hits_total{rule=\"vpn-wireguard\",severity=\"high\"} 2",
		"opengfw_rule_hits_total{rule=\"quote\\\"rule\",severity=\"line\\nseverity\"} 1",
		"opengfw_alert_dropped_total 1",
		"opengfw_allowlist_suppressed_total{reason=\"domain\\\"reason\\nline\"} 1",
		"opengfw_response_applied_total{type=\"ovs\"} 1",
		"opengfw_response_failed_total{type=\"ovs\"} 1",
		"opengfw_streams_total{proto=\"tcp\"} 1",
		"opengfw_streams_total{proto=\"udp\"} 2",
		"opengfw_packet_kernel_packets_total 100",
		"opengfw_packet_kernel_drops_total 7",
		"opengfw_packet_read_errors_total 2",
		"opengfw_packetio_packets_total 100",
		"opengfw_packetio_drops_total 7",
		"opengfw_packetio_read_errors_total 2",
		"# TYPE opengfw_risk_buckets gauge",
		"opengfw_risk_buckets 1",
		"opengfw_risk_events_total{severity=\"high\\\"risk\\nline\"} 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics output does not contain %q:\n%s", want, out)
		}
	}
}

type fakePacketStatsProvider struct {
	stats opengfwio.PacketIOStats
}

func (p fakePacketStatsProvider) Stats() opengfwio.PacketIOStats {
	return p.stats
}

func TestMetricsCollectorHTTPHandler(t *testing.T) {
	m := &metricsCollector{}
	m.IncAlertDropped()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.handleHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if !strings.Contains(rec.Body.String(), "opengfw_alert_dropped_total 1") {
		t.Fatalf("body = %q, want alert dropped metric", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rec = httptest.NewRecorder()
	m.handleHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
