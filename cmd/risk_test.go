package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestRiskAggregationKeyPriority(t *testing.T) {
	event := alertEvent{
		IP: map[string]string{"src": "192.0.2.10"},
		Meta: map[string]string{
			"vm.id":  "vm-100",
			"vm.mac": "52-54-00-00-00-01",
		},
	}
	keyType, key := riskAggregationKey(event)
	if keyType != "vm.id" || key != "vm-100" {
		t.Fatalf("riskAggregationKey() = %q/%q, want vm.id/vm-100", keyType, key)
	}

	delete(event.Meta, "vm.id")
	keyType, key = riskAggregationKey(event)
	if keyType != "vm.mac" || key != "52:54:00:00:00:01" {
		t.Fatalf("riskAggregationKey() = %q/%q, want normalized vm.mac", keyType, key)
	}

	delete(event.Meta, "vm.mac")
	keyType, key = riskAggregationKey(event)
	if keyType != "ip.src" || key != "192.0.2.10" {
		t.Fatalf("riskAggregationKey() = %q/%q, want ip.src/192.0.2.10", keyType, key)
	}
}

func TestRiskAggregatorSendsRiskAlertOncePerWindow(t *testing.T) {
	alert := &recordingAlertSink{}
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r, err := newRiskAggregator(cliConfigRisk{
		Enabled: true,
		Window:  time.Minute,
		Thresholds: cliConfigRiskThresholds{
			Alert: 5,
		},
		Weights: map[string]int{
			"proxy-socks":     2,
			"vpn-wireguard":   4,
			"zero-weight-hit": 0,
		},
	}, alert, nil)
	if err != nil {
		t.Fatalf("newRiskAggregator() error = %v", err)
	}
	metrics := &metricsCollector{}
	r.metrics = metrics
	r.now = func() time.Time { return now }

	r.Add(riskTestEvent("proxy-socks", "vm-100", "52:54:00:00:00:01", "192.0.2.10"))
	if len(alert.events) != 0 {
		t.Fatalf("alert events = %d, want 0 before threshold", len(alert.events))
	}
	r.Add(riskTestEvent("zero-weight-hit", "vm-100", "52:54:00:00:00:01", "192.0.2.10"))
	if len(alert.events) != 0 {
		t.Fatalf("alert events = %d, want 0 for zero weight", len(alert.events))
	}
	r.Add(riskTestEvent("vpn-wireguard", "vm-100", "52:54:00:00:00:01", "192.0.2.10"))
	if len(alert.events) != 1 {
		t.Fatalf("alert events = %d, want 1 when threshold is crossed", len(alert.events))
	}

	event := alert.events[0]
	if event.Type != "risk" {
		t.Fatalf("event.Type = %q, want risk", event.Type)
	}
	if event.Rule != "risk" {
		t.Fatalf("event.Rule = %q, want risk", event.Rule)
	}
	if event.Risk == nil {
		t.Fatal("event.Risk = nil")
	}
	if event.Risk.KeyType != "vm.id" || event.Risk.Key != "vm-100" {
		t.Fatalf("risk key = %q/%q, want vm.id/vm-100", event.Risk.KeyType, event.Risk.Key)
	}
	if event.Risk.Score != 6 {
		t.Fatalf("risk score = %d, want 6", event.Risk.Score)
	}
	if event.Meta["risk.score"] != "6" {
		t.Fatalf("meta risk.score = %q, want 6", event.Meta["risk.score"])
	}
	out := metrics.Render()
	if !strings.Contains(out, `opengfw_risk_events_total{severity="medium"} 1`) {
		t.Fatalf("metrics output missing medium risk event:\n%s", out)
	}
	if got := r.BucketCount(); got != 1 {
		t.Fatalf("BucketCount() = %d, want 1", got)
	}

	r.Add(riskTestEvent("vpn-wireguard", "vm-100", "52:54:00:00:00:01", "192.0.2.10"))
	if len(alert.events) != 1 {
		t.Fatalf("alert events = %d, want no duplicate while still over threshold", len(alert.events))
	}

	now = now.Add(2 * time.Minute)
	r.Add(riskTestEvent("vpn-wireguard", "vm-100", "52:54:00:00:00:01", "192.0.2.10"))
	if len(alert.events) != 1 {
		t.Fatalf("alert events = %d, want no alert after expired single hit below threshold", len(alert.events))
	}
	if got := r.BucketCount(); got != 1 {
		t.Fatalf("BucketCount() after new below-threshold hit = %d, want 1", got)
	}
	r.Add(riskTestEvent("proxy-socks", "vm-100", "52:54:00:00:00:01", "192.0.2.10"))
	if len(alert.events) != 2 {
		t.Fatalf("alert events = %d, want new alert after window resets", len(alert.events))
	}
}

func TestRiskAggregatorResponseThresholdQuarantines(t *testing.T) {
	response := &recordingResponseSink{}
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r, err := newRiskAggregator(cliConfigRisk{
		Enabled: true,
		Window:  time.Minute,
		Thresholds: cliConfigRiskThresholds{
			Alert:    3,
			Response: 7,
		},
		Weights: map[string]int{
			"proxy-socks":   3,
			"vpn-openvpn":   4,
			"vpn-wireguard": 4,
		},
	}, nil, response)
	if err != nil {
		t.Fatalf("newRiskAggregator() error = %v", err)
	}
	r.now = func() time.Time { return now }

	r.Add(riskTestEvent("proxy-socks", "", "52:54:00:00:00:01", "192.0.2.10"))
	if len(response.quarantineEvents) != 0 {
		t.Fatalf("quarantine events = %d, want 0 before response threshold", len(response.quarantineEvents))
	}
	r.Add(riskTestEvent("vpn-openvpn", "", "52:54:00:00:00:01", "192.0.2.10"))
	if len(response.quarantineEvents) != 1 {
		t.Fatalf("quarantine events = %d, want 1 at response threshold", len(response.quarantineEvents))
	}
	if got := response.quarantineEvents[0].Risk.Score; got != 7 {
		t.Fatalf("risk score = %d, want 7", got)
	}
	if response.quarantineEvents[0].Risk.KeyType != "vm.mac" {
		t.Fatalf("risk key type = %q, want vm.mac", response.quarantineEvents[0].Risk.KeyType)
	}

	r.Add(riskTestEvent("vpn-wireguard", "", "52:54:00:00:00:01", "192.0.2.10"))
	if len(response.quarantineEvents) != 1 {
		t.Fatalf("quarantine events = %d, want no duplicate while still over threshold", len(response.quarantineEvents))
	}
}

func TestNewRiskAggregatorDisabledAndInvalidConfig(t *testing.T) {
	r, err := newRiskAggregator(cliConfigRisk{}, nil, nil)
	if err != nil {
		t.Fatalf("disabled newRiskAggregator() error = %v", err)
	}
	if r != nil {
		t.Fatalf("disabled newRiskAggregator() = %#v, want nil", r)
	}

	_, err = newRiskAggregator(cliConfigRisk{Enabled: true}, nil, nil)
	if err == nil {
		t.Fatal("enabled newRiskAggregator() error = nil, want threshold error")
	}
}

func riskTestEvent(rule, vmID, vmMAC, srcIP string) alertEvent {
	meta := map[string]string{}
	if vmID != "" {
		meta["vm.id"] = vmID
	}
	if vmMAC != "" {
		meta["vm.mac"] = vmMAC
	}
	return alertEvent{
		Rule:     rule,
		Severity: "medium",
		ID:       42,
		IP:       map[string]string{"src": srcIP, "dst": "198.51.100.10"},
		Meta:     meta,
	}
}

type recordingAlertSink struct {
	events []alertEvent
}

func (s *recordingAlertSink) Emit(event alertEvent) {
	s.events = append(s.events, event)
}

func (s *recordingAlertSink) Close() {}

type recordingResponseSink struct {
	events           []alertEvent
	quarantineEvents []alertEvent
}

func (s *recordingResponseSink) Emit(event alertEvent) {
	s.events = append(s.events, event)
}

func (s *recordingResponseSink) Quarantine(event alertEvent) {
	s.quarantineEvents = append(s.quarantineEvents, event)
}

func (s *recordingResponseSink) Close() {}
