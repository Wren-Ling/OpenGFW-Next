package cmd

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestSeverityRank(t *testing.T) {
	tests := map[string]int{
		"debug":    1,
		"INFO":     2,
		" low ":    3,
		"medium":   4,
		"high":     5,
		"critical": 6,
		"":         0,
		"unknown":  0,
	}

	for severity, want := range tests {
		if got := severityRank(severity); got != want {
			t.Fatalf("severityRank(%q) = %d, want %d", severity, got, want)
		}
	}
}

func TestOVSResponseShouldHandle(t *testing.T) {
	s := &ovsResponseSink{
		rules:       makeStringSet([]string{"vpn-wireguard"}),
		minSeverity: severityRank("high"),
	}

	tests := []struct {
		name  string
		event alertEvent
		want  bool
	}{
		{
			name:  "explicit rule",
			event: alertEvent{Rule: "vpn-wireguard", Severity: "low"},
			want:  true,
		},
		{
			name:  "severity threshold",
			event: alertEvent{Rule: "other", Severity: "critical"},
			want:  true,
		},
		{
			name:  "below threshold",
			event: alertEvent{Rule: "other", Severity: "medium"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.shouldHandle(tt.event); got != tt.want {
				t.Fatalf("shouldHandle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOVSResponseDropFlow(t *testing.T) {
	s := &ovsResponseSink{
		config: cliConfigOVSResponse{
			Cookie:      "0x1",
			Priority:    1234,
			HardTimeout: 2 * time.Minute,
			IdleTimeout: 1500 * time.Millisecond,
		},
	}

	got := s.dropFlow("dl_src", "52:54:00:00:00:01")
	want := "cookie=0x1,priority=1234,hard_timeout=120,idle_timeout=1,dl_src=52:54:00:00:00:01,actions=drop"
	if got != want {
		t.Fatalf("dropFlow() = %q, want %q", got, want)
	}
}

func TestDurationSeconds(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want int
	}{
		{d: 0, want: 0},
		{d: -time.Second, want: 0},
		{d: time.Nanosecond, want: 1},
		{d: 1500 * time.Millisecond, want: 1},
		{d: 2 * time.Second, want: 2},
	}

	for _, tt := range tests {
		if got := durationSeconds(tt.d); got != tt.want {
			t.Fatalf("durationSeconds(%s) = %d, want %d", tt.d, got, tt.want)
		}
	}
}

func TestOVSResponseUsesInjectedCommandRunner(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	defer func() { logger = oldLogger }()

	var calls [][]string
	s := &ovsResponseSink{
		config: cliConfigOVSResponse{
			Bridge:          "br-test",
			Ofctl:           "ovs-ofctl",
			OpenFlow:        "OpenFlow13",
			Priority:        50000,
			Cookie:          "0x4f474657",
			HardTimeout:     30 * time.Minute,
			CommandTimeout:  time.Second,
			RequireIdentity: boolPtr(true),
		},
		last: make(map[string]time.Time),
		runCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			calls = append(calls, append([]string{name}, args...))
			return []byte("ok"), nil
		},
	}

	event := alertEvent{
		Rule: "vpn-wireguard",
		Meta: map[string]string{"vm.mac": "52-54-00-00-00-01"},
	}
	if err := s.handle(event); err != nil {
		t.Fatalf("handle() error = %v", err)
	}

	want := [][]string{
		{
			"ovs-ofctl",
			"-O",
			"OpenFlow13",
			"add-flow",
			"br-test",
			"cookie=0x4f474657,priority=50000,hard_timeout=1800,dl_src=52:54:00:00:00:01,actions=drop",
		},
		{
			"ovs-ofctl",
			"-O",
			"OpenFlow13",
			"add-flow",
			"br-test",
			"cookie=0x4f474657,priority=50000,hard_timeout=1800,dl_dst=52:54:00:00:00:01,actions=drop",
		},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("command calls = %#v, want %#v", calls, want)
	}
}

func TestOVSResponseCommandRunnerErrorIncludesCommand(t *testing.T) {
	s := &ovsResponseSink{
		config: cliConfigOVSResponse{
			Bridge:         "br-test",
			Ofctl:          "ovs-ofctl",
			CommandTimeout: time.Second,
		},
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("bad flow"), errors.New("exit status 1")
		},
	}

	err := s.addFlow("priority=1,actions=drop")
	if err == nil {
		t.Fatal("addFlow() error = nil")
	}
	for _, want := range []string{"ovs-ofctl add-flow br-test priority=1,actions=drop", "bad flow"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

func TestOVSResponseDeleteCookieFlowsUsesInjectedCommandRunner(t *testing.T) {
	var calls [][]string
	s := &ovsResponseSink{
		config: cliConfigOVSResponse{
			Bridge:         "br-test",
			Ofctl:          "ovs-ofctl",
			OpenFlow:       "OpenFlow13",
			Cookie:         "0x4f474657",
			CommandTimeout: time.Second,
		},
		runCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			calls = append(calls, append([]string{name}, args...))
			return []byte("ok"), nil
		},
	}

	if err := s.deleteCookieFlows(); err != nil {
		t.Fatalf("deleteCookieFlows() error = %v", err)
	}

	want := [][]string{{
		"ovs-ofctl",
		"-O",
		"OpenFlow13",
		"del-flows",
		"br-test",
		"cookie=0x4f474657/-1",
	}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("command calls = %#v, want %#v", calls, want)
	}
}

func TestOVSResponseDeleteCookieFlowsErrorIncludesCommand(t *testing.T) {
	s := &ovsResponseSink{
		config: cliConfigOVSResponse{
			Bridge:         "br-test",
			Ofctl:          "ovs-ofctl",
			Cookie:         "0x4f474657",
			CommandTimeout: time.Second,
		},
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("permission denied"), errors.New("exit status 1")
		},
	}

	err := s.deleteCookieFlows()
	if err == nil {
		t.Fatal("deleteCookieFlows() error = nil")
	}
	for _, want := range []string{"ovs-ofctl del-flows br-test cookie=0x4f474657/-1", "permission denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

func boolPtr(v bool) *bool {
	return &v
}
