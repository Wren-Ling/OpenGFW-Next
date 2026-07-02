package ruleset

import (
	"context"
	"net"
	"strconv"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/modifier"
	"github.com/apernet/OpenGFW/ruleset/builtins/geo"
)

type Action int

const (
	// ActionMaybe indicates that the ruleset hasn't seen anything worth blocking based on
	// current information, but that may change if volatile fields change in the future.
	ActionMaybe Action = iota
	// ActionAllow indicates that the stream should be allowed regardless of future changes.
	ActionAllow
	// ActionBlock indicates that the stream should be blocked.
	ActionBlock
	// ActionDrop indicates that the current packet should be dropped,
	// but the stream should be allowed to continue.
	// Only valid for UDP streams. Equivalent to ActionBlock for TCP streams.
	ActionDrop
	// ActionModify indicates that the current packet should be modified,
	// and the stream should be allowed to continue.
	// Only valid for UDP streams. Equivalent to ActionMaybe for TCP streams.
	ActionModify
)

func (a Action) String() string {
	switch a {
	case ActionMaybe:
		return "maybe"
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionDrop:
		return "drop"
	case ActionModify:
		return "modify"
	default:
		return "unknown"
	}
}

type Protocol int

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

const (
	ProtocolTCP Protocol = iota
	ProtocolUDP
)

type StreamInfo struct {
	ID               int64
	Protocol         Protocol
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Meta             map[string]string
	Props            analyzer.CombinedPropMap
}

func (i StreamInfo) SrcString() string {
	return net.JoinHostPort(i.SrcIP.String(), strconv.Itoa(int(i.SrcPort)))
}

func (i StreamInfo) DstString() string {
	return net.JoinHostPort(i.DstIP.String(), strconv.Itoa(int(i.DstPort)))
}

type MatchResult struct {
	Action      Action
	ModInstance modifier.Instance
}

type MatchMetadata struct {
	Severity string
}

type Ruleset interface {
	// Analyzers returns the list of analyzers to use for a stream.
	// It must be safe for concurrent use by multiple workers.
	Analyzers(StreamInfo) []analyzer.Analyzer
	// Match matches a stream against the ruleset and returns the result.
	// It must be safe for concurrent use by multiple workers.
	Match(StreamInfo) MatchResult
}

// Logger is the logging interface for the ruleset.
type Logger interface {
	Log(info StreamInfo, name string, metadata MatchMetadata)
	MatchError(info StreamInfo, name string, err error)
}

type BuiltinConfig struct {
	Logger               Logger
	GeoMatcher           *geo.GeoMatcher
	ProtectedDialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Fingerprints         FingerprintConfig
}

type FingerprintConfig struct {
	JA3     FingerprintSet `mapstructure:"ja3" yaml:"ja3"`
	JA4     FingerprintSet `mapstructure:"ja4" yaml:"ja4"`
	QUICJA3 FingerprintSet `mapstructure:"quicJa3" yaml:"quicJa3"`
	QUICJA4 FingerprintSet `mapstructure:"quicJa4" yaml:"quicJa4"`
}

type FingerprintSet struct {
	Suspicious []FingerprintEntry `mapstructure:"suspicious" yaml:"suspicious"`
}

type FingerprintEntry struct {
	Hash     string   `mapstructure:"hash" yaml:"hash"`
	Name     string   `mapstructure:"name" yaml:"name"`
	Severity string   `mapstructure:"severity" yaml:"severity"`
	Tags     []string `mapstructure:"tags" yaml:"tags"`
}
