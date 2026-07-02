package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/apernet/OpenGFW/engine"
	opengfwio "github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"
	"github.com/apernet/OpenGFW/ruleset/builtins/geo"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const defaultPCAPSampleManifest = "testdata/pcap/samples.yaml"

type pcapSampleManifest struct {
	Samples []pcapSample `yaml:"samples"`
}

type pcapSample struct {
	Name           string   `yaml:"name"`
	PCAP           string   `yaml:"pcap"`
	ExpectRules    []string `yaml:"expectRules"`
	AllowedRules   []string `yaml:"allowedRules"`
	AllowNoHits    bool     `yaml:"allowNoHits"`
	ExpectMinScore *int     `yaml:"expectMinScore"`
	ExpectMaxScore *int     `yaml:"expectMaxScore"`
}

func TestExampleRulesWithOptionalPCAPSamples(t *testing.T) {
	sampleList := strings.TrimSpace(os.Getenv("OPENGFW_PCAP_SAMPLES"))
	if sampleList == "" {
		t.Skip("set OPENGFW_PCAP_SAMPLES=/path/a.pcap[,/path/b.pcap] to run pcap-driven rule replay")
	}

	rawRules := loadOVSVPNDetectExampleRules(t)
	expectedRules := parsePCAPExpectedRules(os.Getenv("OPENGFW_PCAP_EXPECT_RULES"))
	for _, sample := range strings.Split(sampleList, ",") {
		sample = strings.TrimSpace(sample)
		if sample == "" {
			continue
		}
		t.Run(sample, func(t *testing.T) {
			result := replayExampleRulesPCAP(t, sample, rawRules)
			result.log(t, sample)
			assertPCAPExpectedRules(t, sample, result, expectedRules)
		})
	}
}

func TestExampleRulesWithPCAPManifest(t *testing.T) {
	manifestPath := strings.TrimSpace(os.Getenv("OPENGFW_PCAP_MANIFEST"))
	if manifestPath == "" {
		manifestPath = defaultPCAPSampleManifest
	}
	if _, err := os.Stat(manifestPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("pcap sample manifest %s not found", manifestPath)
		}
		t.Fatalf("stat pcap sample manifest %s: %v", manifestPath, err)
	}

	manifest := loadPCAPSampleManifest(t, manifestPath)
	if len(manifest.Samples) == 0 {
		t.Skipf("pcap sample manifest %s has no samples", manifestPath)
	}

	rawRules := loadOVSVPNDetectExampleRules(t)
	baseDir := filepath.Dir(manifestPath)
	for _, sample := range manifest.Samples {
		sample := sample
		name := sample.Name
		if name == "" {
			name = sample.PCAP
		}
		t.Run(name, func(t *testing.T) {
			if sample.PCAP == "" {
				t.Fatal("sample pcap is required")
			}
			pcapPath := sample.PCAP
			if !filepath.IsAbs(pcapPath) {
				pcapPath = filepath.Join(baseDir, pcapPath)
			}
			if _, err := os.Stat(pcapPath); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					t.Skipf("pcap sample %s not found", pcapPath)
				}
				t.Fatalf("stat pcap sample %s: %v", pcapPath, err)
			}

			result := replayExampleRulesPCAP(t, pcapPath, rawRules)
			result.log(t, name)
			assertPCAPSampleExpectations(t, sample, result)
		})
	}
}

func replayExampleRulesPCAP(t *testing.T, sample string, rawRules []ruleset.ExprRule) pcapReplayResult {
	t.Helper()

	config := loadOVSMirrorConfigForPCAPReplay(t)
	ruleLogger := &pcapReplayRulesetLogger{
		weights: config.Risk.Weights,
	}
	rs, err := ruleset.CompileExprRules(rawRules, analyzers, modifiers, &ruleset.BuiltinConfig{
		Logger:     ruleLogger,
		GeoMatcher: geo.NewGeoMatcher("", ""),
		ProtectedDialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("compile example rules: %v", err)
	}
	packetIO, err := opengfwio.NewPcapPacketIO(opengfwio.PcapPacketIOConfig{PcapFile: sample})
	if err != nil {
		t.Fatalf("open pcap sample %s: %v", sample, err)
	}
	defer packetIO.Close()

	en, err := engine.NewEngine(engine.Config{
		Logger:          pcapReplayEngineLogger{},
		IO:              packetIO,
		Ruleset:         rs,
		Workers:         1,
		WorkerQueueSize: 128,
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := en.Run(ctx); err != nil {
		t.Fatalf("run pcap sample %s: %v", sample, err)
	}
	return ruleLogger.result()
}

func loadPCAPSampleManifest(t *testing.T, path string) pcapSampleManifest {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap sample manifest %s: %v", path, err)
	}
	var manifest pcapSampleManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse pcap sample manifest %s: %v", path, err)
	}
	return manifest
}

func loadOVSMirrorConfigForPCAPReplay(t *testing.T) cliConfig {
	t.Helper()

	v := viper.New()
	v.SetConfigFile(filepath.Join("..", "examples", "ovs-mirror-config.yaml"))
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("read examples/ovs-mirror-config.yaml: %v", err)
	}
	var config cliConfig
	if err := v.Unmarshal(&config); err != nil {
		t.Fatalf("parse examples/ovs-mirror-config.yaml: %v", err)
	}
	return config
}

func assertPCAPExpectedRules(t *testing.T, sample string, result pcapReplayResult, expectedRules map[string]struct{}) {
	t.Helper()
	for rule := range expectedRules {
		if result.Rules[rule].Count == 0 {
			t.Fatalf("pcap sample %s did not hit expected rule %q; hits: %#v", sample, rule, result.Rules)
		}
	}
}

func assertPCAPSampleExpectations(t *testing.T, sample pcapSample, result pcapReplayResult) {
	t.Helper()

	expected := makeStringSet(sample.ExpectRules)
	allowed := makeStringSet(sample.AllowedRules)
	for rule := range expected {
		allowed[rule] = struct{}{}
		if result.Rules[rule].Count == 0 {
			t.Fatalf("sample %q did not hit expected rule %q; hits: %#v", sample.Name, rule, result.Rules)
		}
	}
	if !sample.AllowNoHits && result.Hits == 0 {
		t.Fatalf("sample %q produced no rule hits", sample.Name)
	}
	var unexpected []string
	for rule := range result.Rules {
		if _, ok := allowed[rule]; !ok {
			unexpected = append(unexpected, rule)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("sample %q hit unexpected rules %v; add them to allowedRules if acceptable", sample.Name, unexpected)
	}
	if sample.ExpectMinScore != nil && result.RiskScore < *sample.ExpectMinScore {
		t.Fatalf("sample %q risk score = %d, want >= %d", sample.Name, result.RiskScore, *sample.ExpectMinScore)
	}
	if sample.ExpectMaxScore != nil && result.RiskScore > *sample.ExpectMaxScore {
		t.Fatalf("sample %q risk score = %d, want <= %d", sample.Name, result.RiskScore, *sample.ExpectMaxScore)
	}
}

func parsePCAPExpectedRules(value string) map[string]struct{} {
	rules := make(map[string]struct{})
	for _, rule := range strings.Split(value, ",") {
		rule = strings.TrimSpace(rule)
		if rule != "" {
			rules[rule] = struct{}{}
		}
	}
	return rules
}

type pcapReplayRulesetLogger struct {
	hits      int
	rules     map[string]*pcapReplayRuleHit
	weights   map[string]int
	riskScore int
}

type pcapReplayRuleHit struct {
	Count    int
	Severity string
	Weight   int
}

type pcapReplayResult struct {
	Hits      int
	RiskScore int
	Rules     map[string]pcapReplayRuleHit
}

func (l *pcapReplayRulesetLogger) Log(_ ruleset.StreamInfo, name string, metadata ruleset.MatchMetadata) {
	l.hits++
	if l.rules == nil {
		l.rules = make(map[string]*pcapReplayRuleHit)
	}
	hit := l.rules[name]
	if hit == nil {
		hit = &pcapReplayRuleHit{
			Severity: metadata.Severity,
			Weight:   pcapReplayRuleWeight(l.weights, name),
		}
		l.rules[name] = hit
	}
	hit.Count++
	l.riskScore += hit.Weight
}

func (l *pcapReplayRulesetLogger) result() pcapReplayResult {
	result := pcapReplayResult{
		Hits:      l.hits,
		RiskScore: l.riskScore,
		Rules:     make(map[string]pcapReplayRuleHit, len(l.rules)),
	}
	for rule, hit := range l.rules {
		result.Rules[rule] = *hit
	}
	return result
}

func (r pcapReplayResult) log(t *testing.T, sample string) {
	t.Helper()

	var rules []string
	for rule := range r.Rules {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	t.Logf("pcap sample %s replayed with %d rule hits; risk score=%d", sample, r.Hits, r.RiskScore)
	for _, rule := range rules {
		hit := r.Rules[rule]
		t.Logf("pcap sample %s rule=%s severity=%s count=%d weight=%d contribution=%d",
			sample, rule, hit.Severity, hit.Count, hit.Weight, hit.Count*hit.Weight)
	}
}

func pcapReplayRuleWeight(weights map[string]int, rule string) int {
	if weights == nil {
		return 1
	}
	if weight, ok := weights[rule]; ok {
		return weight
	}
	return 1
}

func (l *pcapReplayRulesetLogger) MatchError(_ ruleset.StreamInfo, name string, err error) {}

type pcapReplayEngineLogger struct{}

func (pcapReplayEngineLogger) WorkerStart(int) {}
func (pcapReplayEngineLogger) WorkerStop(int)  {}
func (pcapReplayEngineLogger) TCPStreamNew(int, ruleset.StreamInfo) {
}
func (pcapReplayEngineLogger) TCPStreamPropUpdate(ruleset.StreamInfo, bool) {}
func (pcapReplayEngineLogger) TCPStreamAction(ruleset.StreamInfo, ruleset.Action, bool) {
}
func (pcapReplayEngineLogger) TCPFlush(int, int, int) {}
func (pcapReplayEngineLogger) UDPStreamNew(int, ruleset.StreamInfo) {
}
func (pcapReplayEngineLogger) UDPStreamPropUpdate(ruleset.StreamInfo, bool) {}
func (pcapReplayEngineLogger) UDPStreamAction(ruleset.StreamInfo, ruleset.Action, bool) {
}
func (pcapReplayEngineLogger) ModifyError(ruleset.StreamInfo, error) {}
func (pcapReplayEngineLogger) AnalyzerDebugf(int64, string, string, ...interface{}) {
}
func (pcapReplayEngineLogger) AnalyzerInfof(int64, string, string, ...interface{}) {
}
func (pcapReplayEngineLogger) AnalyzerErrorf(int64, string, string, ...interface{}) {
}
