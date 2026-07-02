package ruleset

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/apernet/OpenGFW/ruleset/builtins/geo"
)

func TestSuspiciousJA3BuiltinMatchesConfiguredHashes(t *testing.T) {
	logger := &recordingRulesetLogger{}
	rs, err := CompileExprRules([]ExprRule{
		{
			Name:     "tls-hit",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja3("ABCDEF0123456789ABCDEF0123456789")`,
		},
		{
			Name:     "tls-miss",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja3("00000000000000000000000000000000")`,
		},
	}, nil, nil, testBuiltinConfig(logger, FingerprintConfig{
		JA3: FingerprintSet{
			Suspicious: []FingerprintEntry{
				{
					Hash:     "abcdef0123456789abcdef0123456789",
					Name:     "utls-chrome-randomized-example",
					Severity: "medium",
					Tags:     []string{"utls", "proxy"},
				},
			},
		},
	}))
	if err != nil {
		t.Fatalf("CompileExprRules() error = %v", err)
	}

	rs.Match(StreamInfo{})
	if len(logger.logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(logger.logs))
	}
	if logger.logs[0] != "tls-hit" {
		t.Fatalf("logged rule = %q, want tls-hit", logger.logs[0])
	}
}

func TestSuspiciousQUICJA3BuiltinMatchesConfiguredHashes(t *testing.T) {
	logger := &recordingRulesetLogger{}
	rs, err := CompileExprRules([]ExprRule{
		{
			Name:     "quic-hit",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja3("f75253b5e2b4dcb3fdae9b78ce8c6e49")`,
		},
		{
			Name:     "quic-nil-miss",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja3(nil)`,
		},
	}, nil, nil, testBuiltinConfig(logger, FingerprintConfig{
		QUICJA3: FingerprintSet{
			Suspicious: []FingerprintEntry{
				{
					Hash:     "F75253B5E2B4DCB3FDAE9B78CE8C6E49",
					Name:     "quic-proxy-example",
					Severity: "medium",
				},
			},
		},
	}))
	if err != nil {
		t.Fatalf("CompileExprRules() error = %v", err)
	}

	rs.Match(StreamInfo{})
	if len(logger.logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(logger.logs))
	}
	if logger.logs[0] != "quic-hit" {
		t.Fatalf("logged rule = %q, want quic-hit", logger.logs[0])
	}
}

func TestSuspiciousJA4BuiltinMatchesConfiguredFingerprints(t *testing.T) {
	logger := &recordingRulesetLogger{}
	rs, err := CompileExprRules([]ExprRule{
		{
			Name:     "tls-ja4-hit",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja4("t12d160700_8cdfa2d4673b_18dd7303c4a5")`,
		},
		{
			Name:     "tls-ja4-miss",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_ja4("t12d000000_000000000000_000000000000")`,
		},
	}, nil, nil, testBuiltinConfig(logger, FingerprintConfig{
		JA4: FingerprintSet{
			Suspicious: []FingerprintEntry{
				{
					Hash:     "T12D160700_8CDFA2D4673B_18DD7303C4A5",
					Name:     "tls-ja4-example",
					Severity: "medium",
					Tags:     []string{"ja4", "proxy"},
				},
			},
		},
	}))
	if err != nil {
		t.Fatalf("CompileExprRules() error = %v", err)
	}

	rs.Match(StreamInfo{})
	if len(logger.logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(logger.logs))
	}
	if logger.logs[0] != "tls-ja4-hit" {
		t.Fatalf("logged rule = %q, want tls-ja4-hit", logger.logs[0])
	}
}

func TestSuspiciousQUICJA4BuiltinMatchesConfiguredFingerprints(t *testing.T) {
	logger := &recordingRulesetLogger{}
	rs, err := CompileExprRules([]ExprRule{
		{
			Name:     "quic-ja4-hit",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja4("q13d0308p0_55b375c5d22e_f0736a66fa6b")`,
		},
		{
			Name:     "quic-ja4-miss",
			Log:      true,
			Severity: "medium",
			Expr:     `suspicious_quic_ja4(nil)`,
		},
	}, nil, nil, testBuiltinConfig(logger, FingerprintConfig{
		QUICJA4: FingerprintSet{
			Suspicious: []FingerprintEntry{
				{
					Hash:     "Q13D0308P0_55B375C5D22E_F0736A66FA6B",
					Name:     "quic-ja4-example",
					Severity: "medium",
				},
			},
		},
	}))
	if err != nil {
		t.Fatalf("CompileExprRules() error = %v", err)
	}

	rs.Match(StreamInfo{})
	if len(logger.logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(logger.logs))
	}
	if logger.logs[0] != "quic-ja4-hit" {
		t.Fatalf("logged rule = %q, want quic-ja4-hit", logger.logs[0])
	}
}

func testBuiltinConfig(logger Logger, fingerprints FingerprintConfig) *BuiltinConfig {
	return &BuiltinConfig{
		Logger:     logger,
		GeoMatcher: geo.NewGeoMatcher("", ""),
		ProtectedDialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("protected dial is disabled in tests")
		},
		Fingerprints: fingerprints,
	}
}

type recordingRulesetLogger struct {
	logs []string
}

func (l *recordingRulesetLogger) Log(_ StreamInfo, name string, _ MatchMetadata) {
	l.logs = append(l.logs, name)
}

func (l *recordingRulesetLogger) MatchError(StreamInfo, string, error) {}
