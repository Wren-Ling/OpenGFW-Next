package cmd

import (
	"net"
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/ruleset"
	"go.uber.org/zap"
)

func TestAllowlistMatch(t *testing.T) {
	a, err := newAllowlist(cliConfigAllowlist{
		Enabled: true,
		VMIDs:   []string{"vm-100"},
		VMNames: []string{"build-agent-01"},
		MACs:    []string{"52-54-00-00-00-01"},
		IPs:     []string{"192.0.2.10"},
		CIDRs:   []string{"2001:db8:100::/48"},
		Rules:   []string{"vpn-wireguard"},
		Domains: []string{"Example.COM"},
	})
	if err != nil {
		t.Fatalf("newAllowlist() error = %v", err)
	}

	tests := []struct {
		name       string
		event      alertEvent
		wantReason string
		wantValue  string
	}{
		{
			name:       "vm id",
			event:      alertEvent{Meta: map[string]string{"vm.id": "vm-100"}},
			wantReason: "vm.id",
			wantValue:  "vm-100",
		},
		{
			name:       "vm name",
			event:      alertEvent{Meta: map[string]string{"vm.name": "build-agent-01"}},
			wantReason: "vm.name",
			wantValue:  "build-agent-01",
		},
		{
			name:       "mac case insensitive",
			event:      alertEvent{Meta: map[string]string{"l2.src": "52:54:00:00:00:01"}},
			wantReason: "l2.src",
			wantValue:  "52:54:00:00:00:01",
		},
		{
			name:       "ip",
			event:      alertEvent{IP: map[string]string{"src": "192.0.2.10"}},
			wantReason: "ip",
			wantValue:  "192.0.2.10",
		},
		{
			name:       "cidr",
			event:      alertEvent{IP: map[string]string{"dst": "2001:db8:100::1234"}},
			wantReason: "cidr",
			wantValue:  "2001:db8:100::/48",
		},
		{
			name:       "rule",
			event:      alertEvent{Rule: "vpn-wireguard"},
			wantReason: "rule",
			wantValue:  "vpn-wireguard",
		},
		{
			name: "tls sni domain case insensitive subdomain",
			event: alertEvent{Props: analyzer.CombinedPropMap{
				"tls": analyzer.PropMap{"req": analyzer.PropMap{"sni": "API.EXAMPLE.com."}},
			}},
			wantReason: "domain",
			wantValue:  "example.com",
		},
		{
			name: "dns question domain",
			event: alertEvent{Props: analyzer.CombinedPropMap{
				"dns": analyzer.PropMap{"questions": []analyzer.PropMap{
					{"name": "www.example.com."},
				}},
			}},
			wantReason: "domain",
			wantValue:  "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := a.Match(tt.event)
			if !ok {
				t.Fatal("Match() = false, want true")
			}
			if got.Reason != tt.wantReason || got.Value != tt.wantValue {
				t.Fatalf("Match() = %#v, want reason/value %q/%q", got, tt.wantReason, tt.wantValue)
			}
		})
	}
}

func TestAllowlistDefaultsAndInvalidConfig(t *testing.T) {
	a, err := newAllowlist(cliConfigAllowlist{Enabled: true})
	if err != nil {
		t.Fatalf("newAllowlist() error = %v", err)
	}
	if !a.LogSuppressed() {
		t.Fatal("LogSuppressed() = false, want default true")
	}
	if a.WebhookSuppressed() {
		t.Fatal("WebhookSuppressed() = true, want default false")
	}

	logSuppressed := false
	a, err = newAllowlist(cliConfigAllowlist{Enabled: true, LogSuppressed: &logSuppressed})
	if err != nil {
		t.Fatalf("newAllowlist() with logSuppressed=false error = %v", err)
	}
	if a.LogSuppressed() {
		t.Fatal("LogSuppressed() = true, want configured false")
	}

	if _, err := newAllowlist(cliConfigAllowlist{Enabled: true, CIDRs: []string{"bad-cidr"}}); err == nil {
		t.Fatal("newAllowlist() invalid cidr error = nil")
	}
	if _, err := newAllowlist(cliConfigAllowlist{Enabled: true, MACs: []string{"bad-mac"}}); err == nil {
		t.Fatal("newAllowlist() invalid mac error = nil")
	}
}

func TestRulesetLoggerSuppressesAllowlistedEvents(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	defer func() { logger = oldLogger }()

	alert := &recordingAlertSink{}
	response := &recordingResponseSink{}
	risk, err := newRiskAggregator(cliConfigRisk{
		Enabled: true,
		Thresholds: cliConfigRiskThresholds{
			Alert:    1,
			Response: 1,
		},
	}, alert, response)
	if err != nil {
		t.Fatalf("newRiskAggregator() error = %v", err)
	}
	a, err := newAllowlist(cliConfigAllowlist{
		Enabled: true,
		Rules:   []string{"vpn-wireguard"},
	})
	if err != nil {
		t.Fatalf("newAllowlist() error = %v", err)
	}

	metrics := &metricsCollector{}
	l := &rulesetLogger{
		Alert:     alert,
		Risk:      risk,
		Response:  response,
		Metrics:   metrics,
		Allowlist: a,
	}
	l.Log(allowlistTestStreamInfo(), "vpn-wireguard", ruleset.MatchMetadata{Severity: "high"})

	if len(alert.events) != 0 {
		t.Fatalf("alert events = %d, want 0 for default suppressed webhook", len(alert.events))
	}
	if len(response.events) != 0 {
		t.Fatalf("response events = %d, want 0 for allowlisted direct response", len(response.events))
	}
	if len(response.quarantineEvents) != 0 {
		t.Fatalf("quarantine events = %d, want 0 for allowlisted risk response", len(response.quarantineEvents))
	}
	out := metrics.Render()
	if !strings.Contains(out, `opengfw_allowlist_suppressed_total{reason="rule"} 1`) {
		t.Fatalf("metrics output missing allowlist suppression counter:\n%s", out)
	}
}

func TestRulesetLoggerCanWebhookSuppressedEvents(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	defer func() { logger = oldLogger }()

	alert := &recordingAlertSink{}
	response := &recordingResponseSink{}
	risk, err := newRiskAggregator(cliConfigRisk{
		Enabled: true,
		Thresholds: cliConfigRiskThresholds{
			Alert:    1,
			Response: 1,
		},
	}, alert, response)
	if err != nil {
		t.Fatalf("newRiskAggregator() error = %v", err)
	}
	a, err := newAllowlist(cliConfigAllowlist{
		Enabled:           true,
		Rules:             []string{"vpn-wireguard"},
		WebhookSuppressed: true,
	})
	if err != nil {
		t.Fatalf("newAllowlist() error = %v", err)
	}

	l := &rulesetLogger{
		Alert:     alert,
		Risk:      risk,
		Response:  response,
		Metrics:   &metricsCollector{},
		Allowlist: a,
	}
	l.Log(allowlistTestStreamInfo(), "vpn-wireguard", ruleset.MatchMetadata{Severity: "high"})

	if len(alert.events) != 1 {
		t.Fatalf("alert events = %d, want 1 suppressed webhook", len(alert.events))
	}
	if !alert.events[0].Suppressed {
		t.Fatal("suppressed webhook event Suppressed = false")
	}
	if alert.events[0].SuppressionReason != "rule" || alert.events[0].SuppressionValue != "vpn-wireguard" {
		t.Fatalf("suppression = %q/%q, want rule/vpn-wireguard", alert.events[0].SuppressionReason, alert.events[0].SuppressionValue)
	}
	if len(response.events) != 0 || len(response.quarantineEvents) != 0 {
		t.Fatalf("response events = %d quarantine = %d, want both 0", len(response.events), len(response.quarantineEvents))
	}
}

func allowlistTestStreamInfo() ruleset.StreamInfo {
	return ruleset.StreamInfo{
		ID:       42,
		Protocol: ruleset.ProtocolUDP,
		SrcIP:    net.ParseIP("192.0.2.10"),
		DstIP:    net.ParseIP("198.51.100.10"),
		SrcPort:  51820,
		DstPort:  51820,
		Meta: map[string]string{
			"vm.id":  "vm-100",
			"vm.mac": "52:54:00:00:00:01",
		},
	}
}
