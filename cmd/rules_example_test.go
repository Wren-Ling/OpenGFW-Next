package cmd

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/ruleset"
	"github.com/apernet/OpenGFW/ruleset/builtins/geo"
)

type noopRulesetLogger struct{}

func (noopRulesetLogger) Log(ruleset.StreamInfo, string, ruleset.MatchMetadata) {}

func (noopRulesetLogger) MatchError(ruleset.StreamInfo, string, error) {}

func TestOVSVPNDetectExampleRulesCompile(t *testing.T) {
	rawRules := loadOVSVPNDetectExampleRules(t)
	if err := compileExprRulesWithDefaults(rawRules); err != nil {
		t.Fatalf("compile examples/ovs-vpn-detect-rules.yaml: %v", err)
	}
}

func TestModernProxyWeakSignalRulesAreAlertOnly(t *testing.T) {
	rawRules := loadOVSVPNDetectExampleRules(t)
	weakSignalRules := modernProxyWeakSignalRules()
	seen := make(map[string]struct{})
	for _, rule := range rawRules {
		if _, ok := weakSignalRules[rule.Name]; !ok {
			continue
		}
		seen[rule.Name] = struct{}{}
		if !rule.Log {
			t.Fatalf("rule %q Log = false, want alert-only log rule", rule.Name)
		}
		if rule.Action != "" {
			t.Fatalf("rule %q action = %q, want empty action", rule.Name, rule.Action)
		}
	}
	for rule := range weakSignalRules {
		if _, ok := seen[rule]; !ok {
			t.Fatalf("missing weak signal rule %q", rule)
		}
	}
}

func TestModernProxyWeakSignalRulesNotInOVSResponse(t *testing.T) {
	config := loadOVSMirrorConfigForPCAPReplay(t)
	weakSignalRules := modernProxyWeakSignalRules()
	for _, rule := range config.Response.OVS.Rules {
		if _, ok := weakSignalRules[rule]; ok {
			t.Fatalf("response.ovs.rules contains weak signal rule %q; modern proxy candidates must stay risk/log-only by default", rule)
		}
	}
}

func TestOVSVPNDetectExampleRulesCompileRejectsInvalidRules(t *testing.T) {
	rawRules := loadOVSVPNDetectExampleRules(t)
	tests := []struct {
		name    string
		mutate  func([]ruleset.ExprRule)
		wantErr string
	}{
		{
			name: "invalid severity",
			mutate: func(rules []ruleset.ExprRule) {
				rules[0].Severity = "urgent"
			},
			wantErr: "invalid severity",
		},
		{
			name: "unknown analyzer",
			mutate: func(rules []ruleset.ExprRule) {
				rules[0].Expr = "missing_analyzer.yes == true"
			},
			wantErr: "unknown analyzer or identifier",
		},
		{
			name: "invalid expression",
			mutate: func(rules []ruleset.ExprRule) {
				rules[0].Expr = "wireguard.message_type !="
			},
			wantErr: "invalid expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := append([]ruleset.ExprRule(nil), rawRules...)
			tt.mutate(rules)
			err := compileExprRulesWithDefaults(rules)
			if err == nil {
				t.Fatal("compile succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("compile error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func modernProxyWeakSignalRules() map[string]struct{} {
	return map[string]struct{}{
		"udp443-long-lived-no-quic-sni":               {},
		"hysteria2-quic-like-weak-signal":             {},
		"hysteria2-custom-udp-weak-signal":            {},
		"tuic-quic-like-weak-signal":                  {},
		"tuic-short-quic-burst-weak-signal":           {},
		"masque-connect-udp-weak-signal":              {},
		"tls-vless-reality-domain-weak-signal":        {},
		"tls-shadowtls-anytls-domain-weak-signal":     {},
		"dns-vless-reality-domain-weak-signal":        {},
		"dns-shadowtls-anytls-domain-weak-signal":     {},
		"dns-tcp-vless-reality-domain-weak-signal":    {},
		"dns-tcp-shadowtls-anytls-domain-weak-signal": {},
	}
}

func loadOVSVPNDetectExampleRules(t *testing.T) []ruleset.ExprRule {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "examples", "ovs-vpn-detect-rules.yaml")
	rawRules, err := ruleset.ExprRulesFromYAML(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return rawRules
}

func compileExprRulesWithDefaults(rawRules []ruleset.ExprRule) error {
	_, err := ruleset.CompileExprRules(rawRules, analyzers, modifiers, &ruleset.BuiltinConfig{
		Logger:     noopRulesetLogger{},
		GeoMatcher: geo.NewGeoMatcher("", ""),
		ProtectedDialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("protected dial is disabled in tests")
		},
	})
	return err
}
