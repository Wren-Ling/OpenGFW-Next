package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/ruleset"
	"github.com/apernet/OpenGFW/ruleset/builtins/geo"
	"github.com/spf13/viper"
)

func TestFingerprintConfigLoadsFromYAMLAndCompilesBuiltins(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
fingerprints:
  ja3:
    suspicious:
      - hash: "ABCDEF0123456789ABCDEF0123456789"
        name: "example-utls"
        tags: ["utls", "proxy"]
  ja4:
    suspicious:
      - hash: "T12D160700_8CDFA2D4673B_18DD7303C4A5"
        name: "example-tls-ja4"
        tags: ["ja4", "proxy"]
  quicJa3:
    suspicious:
      - hash: "F75253B5E2B4DCB3FDAE9B78CE8C6E49"
        name: "example-quic"
  quicJa4:
    suspicious:
      - hash: "Q13D0308P0_55B375C5D22E_F0736A66FA6B"
        name: "example-quic-ja4"
`)); err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}

	var config cliConfig
	if err := v.Unmarshal(&config); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	logger := &fingerprintConfigTestLogger{}
	rs, err := ruleset.CompileExprRules([]ruleset.ExprRule{
		{
			Name:     "tls-ja3-fingerprint",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja3("abcdef0123456789abcdef0123456789")`,
		},
		{
			Name:     "tls-ja4-fingerprint",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja4("t12d160700_8cdfa2d4673b_18dd7303c4a5")`,
		},
		{
			Name:     "quic-ja3-fingerprint",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja3("f75253b5e2b4dcb3fdae9b78ce8c6e49")`,
		},
		{
			Name:     "quic-ja4-fingerprint",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja4("q13d0308p0_55b375c5d22e_f0736a66fa6b")`,
		},
	}, analyzers, modifiers, &ruleset.BuiltinConfig{
		Logger:     logger,
		GeoMatcher: geo.NewGeoMatcher("", ""),
		ProtectedDialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("protected dial is disabled in tests")
		},
		Fingerprints: config.Fingerprints,
	})
	if err != nil {
		t.Fatalf("CompileExprRules() error = %v", err)
	}

	rs.Match(ruleset.StreamInfo{})
	if got, want := strings.Join(logger.logs, ","), "tls-ja3-fingerprint,tls-ja4-fingerprint,quic-ja3-fingerprint,quic-ja4-fingerprint"; got != want {
		t.Fatalf("logged rules = %q, want %q", got, want)
	}
}

func TestFingerprintConfigLoadsExternalFilesAndMatches(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "fingerprints"), 0755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	ja3Path := filepath.Join(dir, "fingerprints", "ja3.yaml")
	if err := os.WriteFile(ja3Path, []byte(`
suspicious:
  - hash: "ABCDEF0123456789ABCDEF0123456789"
    name: "mihomo-lab-ja3"
    severity: medium
    tags: ["mihomo", "lab"]
`), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	quicJA4Path := filepath.Join(dir, "fingerprints", "quic-ja4.yaml")
	if err := os.WriteFile(quicJA4Path, []byte(`
fingerprints:
  quicJa4:
    suspicious:
      - hash: "Q13D0308P0_55B375C5D22E_F0736A66FA6B"
        name: "xray-reality-quic-ja4"
        severity: medium
`), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
fingerprints:
  ja3:
    files:
      - fingerprints/ja3.yaml
  quicJa4:
    files:
      - fingerprints/quic-ja4.yaml
`)); err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}
	var config cliConfig
	if err := v.Unmarshal(&config); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if err := config.loadExternalDatasets(configPath); err != nil {
		t.Fatalf("loadExternalDatasets() error = %v", err)
	}

	logger := &fingerprintConfigTestLogger{}
	rs, err := ruleset.CompileExprRules([]ruleset.ExprRule{
		{
			Name:     "external-ja3-hit",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja3("abcdef0123456789abcdef0123456789")`,
		},
		{
			Name:     "external-ja3-miss",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja3("00000000000000000000000000000000")`,
		},
		{
			Name:     "external-quic-ja4-hit",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja4("q13d0308p0_55b375c5d22e_f0736a66fa6b")`,
		},
	}, analyzers, modifiers, &ruleset.BuiltinConfig{
		Logger:     logger,
		GeoMatcher: geo.NewGeoMatcher("", ""),
		ProtectedDialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("protected dial is disabled in tests")
		},
		Fingerprints: config.Fingerprints,
	})
	if err != nil {
		t.Fatalf("CompileExprRules() error = %v", err)
	}

	rs.Match(ruleset.StreamInfo{})
	if got, want := strings.Join(logger.logs, ","), "external-ja3-hit,external-quic-ja4-hit"; got != want {
		t.Fatalf("logged rules = %q, want %q", got, want)
	}
}

type fingerprintConfigTestLogger struct {
	logs []string
}

func (l *fingerprintConfigTestLogger) Log(_ ruleset.StreamInfo, name string, _ ruleset.MatchMetadata) {
	l.logs = append(l.logs, name)
}

func (l *fingerprintConfigTestLogger) MatchError(ruleset.StreamInfo, string, error) {}
