package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	defaultOVSResponsePriority       = 50000
	defaultOVSResponseHardTimeout    = 30 * time.Minute
	defaultOVSResponseCooldown       = 5 * time.Minute
	defaultOVSResponseQueueSize      = 256
	defaultOVSResponseCommandTimeout = 3 * time.Second
)

type cliConfigResponse struct {
	OVS cliConfigOVSResponse `mapstructure:"ovs"`
}

type cliConfigOVSResponse struct {
	Enabled         bool          `mapstructure:"enabled"`
	Bridge          string        `mapstructure:"bridge"`
	Rules           []string      `mapstructure:"rules"`
	MinSeverity     string        `mapstructure:"minSeverity"`
	Ofctl           string        `mapstructure:"ofctl"`
	OpenFlow        string        `mapstructure:"openFlow"`
	Priority        int           `mapstructure:"priority"`
	Cookie          string        `mapstructure:"cookie"`
	DeleteOnStart   bool          `mapstructure:"deleteOnStart"`
	HardTimeout     time.Duration `mapstructure:"hardTimeout"`
	IdleTimeout     time.Duration `mapstructure:"idleTimeout"`
	Cooldown        time.Duration `mapstructure:"cooldown"`
	QueueSize       int           `mapstructure:"queueSize"`
	CommandTimeout  time.Duration `mapstructure:"commandTimeout"`
	RequireIdentity *bool         `mapstructure:"requireIdentity"`
}

type responseSink interface {
	Emit(alertEvent)
	Quarantine(alertEvent)
	Close()
}

type ovsResponseSink struct {
	config      cliConfigOVSResponse
	rules       map[string]struct{}
	minSeverity int
	events      chan alertEvent
	stop        chan struct{}
	done        chan struct{}
	last        map[string]time.Time
	runCommand  commandRunner
	metrics     *metricsCollector
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func newResponseSink(config cliConfigResponse, metrics *metricsCollector) (responseSink, error) {
	if !config.OVS.Enabled {
		return nil, nil
	}
	ovsConfig := config.OVS
	if ovsConfig.Bridge == "" {
		return nil, errors.New("response.ovs.bridge is required")
	}
	minSeverity := severityRank(ovsConfig.MinSeverity)
	if ovsConfig.MinSeverity != "" && minSeverity == 0 {
		return nil, fmt.Errorf("response.ovs.minSeverity %q is invalid", ovsConfig.MinSeverity)
	}
	if len(ovsConfig.Rules) == 0 && minSeverity == 0 {
		return nil, errors.New("response.ovs.rules or response.ovs.minSeverity is required")
	}
	if ovsConfig.Ofctl == "" {
		ovsConfig.Ofctl = "ovs-ofctl"
	}
	if ovsConfig.Priority <= 0 {
		ovsConfig.Priority = defaultOVSResponsePriority
	}
	if ovsConfig.Cookie == "" {
		ovsConfig.Cookie = "0x4f474657"
	}
	if ovsConfig.HardTimeout <= 0 {
		ovsConfig.HardTimeout = defaultOVSResponseHardTimeout
	}
	if ovsConfig.Cooldown <= 0 {
		ovsConfig.Cooldown = defaultOVSResponseCooldown
	}
	if ovsConfig.QueueSize <= 0 {
		ovsConfig.QueueSize = defaultOVSResponseQueueSize
	}
	if ovsConfig.CommandTimeout <= 0 {
		ovsConfig.CommandTimeout = defaultOVSResponseCommandTimeout
	}

	s := &ovsResponseSink{
		config:      ovsConfig,
		rules:       makeStringSet(ovsConfig.Rules),
		minSeverity: minSeverity,
		events:      make(chan alertEvent, ovsConfig.QueueSize),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		last:        make(map[string]time.Time),
		runCommand:  execCommandRunner,
		metrics:     metrics,
	}
	if ovsConfig.DeleteOnStart {
		if err := s.deleteCookieFlows(); err != nil && logger != nil {
			logger.Warn("failed to delete old ovs quarantine flows",
				zap.String("bridge", s.config.Bridge),
				zap.String("cookie", s.config.Cookie),
				zap.Error(err))
		}
	}
	go s.run()
	return s, nil
}

func (s *ovsResponseSink) Emit(event alertEvent) {
	if !s.shouldHandle(event) {
		return
	}
	s.enqueue(event)
}

func (s *ovsResponseSink) Quarantine(event alertEvent) {
	s.enqueue(event)
}

func (s *ovsResponseSink) enqueue(event alertEvent) {
	select {
	case s.events <- event:
	case <-s.stop:
	default:
		logger.Warn("response queue full, dropping event",
			zap.String("rule", event.Rule),
			zap.Int64("id", event.ID))
	}
}

func (s *ovsResponseSink) shouldHandle(event alertEvent) bool {
	if _, ok := s.rules[event.Rule]; ok {
		return true
	}
	if s.minSeverity > 0 && severityRank(event.Severity) >= s.minSeverity {
		return true
	}
	return false
}

func (s *ovsResponseSink) Close() {
	close(s.stop)
	<-s.done
}

func (s *ovsResponseSink) run() {
	defer close(s.done)
	for {
		select {
		case event := <-s.events:
			if err := s.handle(event); err != nil {
				s.metrics.IncResponseFailed("ovs")
				logger.Warn("failed to apply response",
					zap.String("rule", event.Rule),
					zap.Int64("id", event.ID),
					zap.Error(err))
			}
		case <-s.stop:
			return
		}
	}
}

func (s *ovsResponseSink) handle(event alertEvent) error {
	mac, err := s.responseMAC(event)
	if err != nil {
		return err
	}
	now := time.Now()
	if last, ok := s.last[mac]; ok && now.Sub(last) < s.config.Cooldown {
		return nil
	}
	s.last[mac] = now

	for _, field := range []string{"dl_src", "dl_dst"} {
		flow := s.dropFlow(field, mac)
		if err := s.addFlow(flow); err != nil {
			return err
		}
	}
	logger.Info("ovs quarantine flow installed",
		zap.String("rule", event.Rule),
		zap.String("bridge", s.config.Bridge),
		zap.String("mac", mac),
		zap.Duration("hardTimeout", s.config.HardTimeout))
	s.metrics.IncResponseApplied("ovs")
	return nil
}

func (s *ovsResponseSink) responseMAC(event alertEvent) (string, error) {
	mac := normalizeMAC(event.Meta["vm.mac"])
	requireIdentity := true
	if s.config.RequireIdentity != nil {
		requireIdentity = *s.config.RequireIdentity
	}
	if mac == "" && !requireIdentity {
		mac = normalizeMAC(event.Meta["l2.src"])
		if mac == "" {
			mac = normalizeMAC(event.Meta["l2.dst"])
		}
	}
	if mac == "" {
		return "", errors.New("no vm.mac metadata on response event")
	}
	if _, err := net.ParseMAC(mac); err != nil {
		return "", fmt.Errorf("invalid response mac %q: %w", mac, err)
	}
	return mac, nil
}

func (s *ovsResponseSink) dropFlow(field, mac string) string {
	parts := []string{
		"cookie=" + s.config.Cookie,
		"priority=" + strconv.Itoa(s.config.Priority),
	}
	if hardTimeout := durationSeconds(s.config.HardTimeout); hardTimeout > 0 {
		parts = append(parts, "hard_timeout="+strconv.Itoa(hardTimeout))
	}
	if idleTimeout := durationSeconds(s.config.IdleTimeout); idleTimeout > 0 {
		parts = append(parts, "idle_timeout="+strconv.Itoa(idleTimeout))
	}
	parts = append(parts, field+"="+mac, "actions=drop")
	return strings.Join(parts, ",")
}

func (s *ovsResponseSink) addFlow(flow string) error {
	_, err := s.ovsCommand("add-flow", s.config.Bridge, flow)
	return err
}

func (s *ovsResponseSink) deleteCookieFlows() error {
	_, err := s.ovsCommand("del-flows", s.config.Bridge, "cookie="+s.config.Cookie+"/-1")
	return err
}

func (s *ovsResponseSink) ovsCommand(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.CommandTimeout)
	defer cancel()

	fullArgs := []string{}
	if s.config.OpenFlow != "" {
		fullArgs = append(fullArgs, "-O", s.config.OpenFlow)
	}
	fullArgs = append(fullArgs, args...)

	runCommand := s.runCommand
	if runCommand == nil {
		runCommand = execCommandRunner
	}
	output, err := runCommand(ctx, s.config.Ofctl, fullArgs...)
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", s.config.Ofctl, strings.Join(fullArgs, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func execCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func durationSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	seconds := int(d / time.Second)
	if seconds <= 0 {
		return 1
	}
	return seconds
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "debug":
		return 1
	case "info":
		return 2
	case "low":
		return 3
	case "medium":
		return 4
	case "high":
		return 5
	case "critical":
		return 6
	default:
		return 0
	}
}
