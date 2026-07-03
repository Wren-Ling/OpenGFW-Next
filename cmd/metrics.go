package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	opengfwio "github.com/apernet/OpenGFW/io"

	"go.uber.org/zap"
)

const (
	defaultMetricsListen               = "127.0.0.1:9090"
	defaultMetricsPath                 = "/metrics"
	defaultPacketStatsInterval         = 30 * time.Second
	defaultPacketDropWarnRate  float64 = 0.01
)

type cliConfigMetrics struct {
	Enabled             bool          `mapstructure:"enabled"`
	Listen              string        `mapstructure:"listen"`
	Path                string        `mapstructure:"path"`
	PacketStatsInterval time.Duration `mapstructure:"packetStatsInterval"`
	PacketDropWarnRate  *float64      `mapstructure:"packetDropWarnRate"`
}

type metricsEndpoint struct {
	collector *metricsCollector
	server    *http.Server
	listener  net.Listener
}

type metricsCollector struct {
	alertDropped atomic.Uint64

	packetIO opengfwio.PacketIOStatsProvider
	risk     *riskAggregator

	ruleHits            labeledCounters2
	allowlistSuppressed labeledCounters1
	responseApplied     labeledCounters1
	responseFailed      labeledCounters1
	streamsTotal        labeledCounters1
	riskEvents          labeledCounters1
}

type labeledCounter struct {
	value atomic.Uint64
}

type labeledCounters1 struct {
	m sync.Map
}

type labeledCounters2 struct {
	m sync.Map
}

func newMetricsEndpoint(config cliConfigMetrics) (*metricsEndpoint, error) {
	if !config.Enabled {
		return nil, nil
	}
	if config.Listen == "" {
		config.Listen = defaultMetricsListen
	}
	if config.Path == "" {
		config.Path = defaultMetricsPath
	}
	if !strings.HasPrefix(config.Path, "/") {
		config.Path = "/" + config.Path
	}

	collector := &metricsCollector{}
	mux := http.NewServeMux()
	mux.HandleFunc(config.Path, collector.handleHTTP)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}
	endpoint := &metricsEndpoint{
		collector: collector,
		server:    server,
		listener:  listener,
	}
	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed && logger != nil {
			logger.Error("metrics server exited", zap.Error(err))
		}
	}()
	return endpoint, nil
}

func (e *metricsEndpoint) Close() {
	if e == nil || e.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = e.server.Shutdown(ctx)
}

func (e *metricsEndpoint) Collector() *metricsCollector {
	if e == nil {
		return nil
	}
	return e.collector
}

func (m *metricsCollector) IncRuleHit(rule, severity string) {
	if m == nil {
		return
	}
	m.ruleHits.Add(rule, severity, 1)
}

func (m *metricsCollector) IncAlertDropped() {
	if m == nil {
		return
	}
	m.alertDropped.Add(1)
}

func (m *metricsCollector) IncAllowlistSuppressed(reason string) {
	if m == nil {
		return
	}
	m.allowlistSuppressed.Add(reason, 1)
}

func (m *metricsCollector) IncResponseApplied(responseType string) {
	if m == nil {
		return
	}
	m.responseApplied.Add(responseType, 1)
}

func (m *metricsCollector) IncResponseFailed(responseType string) {
	if m == nil {
		return
	}
	m.responseFailed.Add(responseType, 1)
}

func (m *metricsCollector) IncStream(proto string) {
	if m == nil {
		return
	}
	m.streamsTotal.Add(proto, 1)
}

func (m *metricsCollector) IncRiskEvent(severity string) {
	if m == nil {
		return
	}
	m.riskEvents.Add(severity, 1)
}

func (m *metricsCollector) SetPacketIO(packetIO opengfwio.PacketIO) {
	if m == nil {
		return
	}
	provider, ok := packetIO.(opengfwio.PacketIOStatsProvider)
	if !ok {
		return
	}
	m.packetIO = provider
}

func (m *metricsCollector) SetRiskAggregator(risk *riskAggregator) {
	if m == nil {
		return
	}
	m.risk = risk
}

func (m *metricsCollector) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(m.Render()))
}

func (m *metricsCollector) Render() string {
	if m == nil {
		return ""
	}
	var b strings.Builder
	writeMetricHelp(&b, "opengfw_rule_hits_total", "Total ruleset log hits by rule and severity.")
	for _, sample := range m.ruleHits.Samples() {
		fmt.Fprintf(&b, "opengfw_rule_hits_total{rule=\"%s\",severity=\"%s\"} %d\n",
			escapePromLabel(sample.Labels[0]), escapePromLabel(sample.Labels[1]), sample.Value)
	}
	writeMetricHelp(&b, "opengfw_alert_dropped_total", "Total alert events dropped before delivery.")
	fmt.Fprintf(&b, "opengfw_alert_dropped_total %d\n", m.alertDropped.Load())
	writeMetricHelp(&b, "opengfw_allowlist_suppressed_total", "Total rule hits suppressed by allowlist reason.")
	for _, sample := range m.allowlistSuppressed.Samples() {
		fmt.Fprintf(&b, "opengfw_allowlist_suppressed_total{reason=\"%s\"} %d\n",
			escapePromLabel(sample.Labels[0]), sample.Value)
	}
	writeMetricHelp(&b, "opengfw_response_applied_total", "Total response actions successfully applied by type.")
	for _, sample := range m.responseApplied.Samples() {
		fmt.Fprintf(&b, "opengfw_response_applied_total{type=\"%s\"} %d\n",
			escapePromLabel(sample.Labels[0]), sample.Value)
	}
	writeMetricHelp(&b, "opengfw_response_failed_total", "Total response actions that failed by type.")
	for _, sample := range m.responseFailed.Samples() {
		fmt.Fprintf(&b, "opengfw_response_failed_total{type=\"%s\"} %d\n",
			escapePromLabel(sample.Labels[0]), sample.Value)
	}
	writeMetricHelp(&b, "opengfw_streams_total", "Total streams observed by protocol.")
	for _, sample := range m.streamsTotal.Samples() {
		fmt.Fprintf(&b, "opengfw_streams_total{proto=\"%s\"} %d\n",
			escapePromLabel(sample.Labels[0]), sample.Value)
	}
	packetStats := m.packetIOStats()
	writeMetricHelp(&b, "opengfw_packet_kernel_packets_total", "Total packets reported by packet IO kernel statistics.")
	fmt.Fprintf(&b, "opengfw_packet_kernel_packets_total %d\n", packetStats.Packets)
	writeMetricHelp(&b, "opengfw_packet_kernel_drops_total", "Total packets dropped according to packet IO kernel statistics.")
	fmt.Fprintf(&b, "opengfw_packet_kernel_drops_total %d\n", packetStats.Drops)
	writeMetricHelpType(&b, "opengfw_packet_kernel_drop_rate", "Cumulative packet IO kernel drop ratio, drops divided by packets plus drops.", "gauge")
	fmt.Fprintf(&b, "opengfw_packet_kernel_drop_rate %.9g\n", opengfwio.PacketIODropRate(packetStats.Packets, packetStats.Drops))
	writeMetricHelp(&b, "opengfw_packet_read_errors_total", "Total non-timeout packet IO read errors.")
	fmt.Fprintf(&b, "opengfw_packet_read_errors_total %d\n", packetStats.ReadErrors)
	writeMetricHelp(&b, "opengfw_packet_ring_losing_blocks_total", "Total TPACKET_V3 blocks observed with TP_STATUS_LOSING.")
	fmt.Fprintf(&b, "opengfw_packet_ring_losing_blocks_total %d\n", packetStats.RingLosingBlocks)
	writeMetricHelp(&b, "opengfw_packetio_packets_total", "Total packets observed by packet IO implementations that expose kernel statistics.")
	fmt.Fprintf(&b, "opengfw_packetio_packets_total %d\n", packetStats.Packets)
	writeMetricHelp(&b, "opengfw_packetio_drops_total", "Total packets dropped by packet IO implementations that expose kernel statistics.")
	fmt.Fprintf(&b, "opengfw_packetio_drops_total %d\n", packetStats.Drops)
	writeMetricHelpType(&b, "opengfw_packetio_drop_rate", "Cumulative packet IO drop ratio alias for existing dashboards.", "gauge")
	fmt.Fprintf(&b, "opengfw_packetio_drop_rate %.9g\n", opengfwio.PacketIODropRate(packetStats.Packets, packetStats.Drops))
	writeMetricHelp(&b, "opengfw_packetio_read_errors_total", "Total non-timeout packet IO read errors.")
	fmt.Fprintf(&b, "opengfw_packetio_read_errors_total %d\n", packetStats.ReadErrors)
	writeMetricHelp(&b, "opengfw_packetio_ring_losing_blocks_total", "Total TPACKET_V3 TP_STATUS_LOSING block observations alias for existing dashboards.")
	fmt.Fprintf(&b, "opengfw_packetio_ring_losing_blocks_total %d\n", packetStats.RingLosingBlocks)
	writeMetricHelpType(&b, "opengfw_risk_buckets", "Current number of active risk aggregation buckets.", "gauge")
	fmt.Fprintf(&b, "opengfw_risk_buckets %d\n", m.riskBucketCount())
	writeMetricHelp(&b, "opengfw_risk_events_total", "Total aggregated risk events by severity.")
	for _, sample := range m.riskEvents.Samples() {
		fmt.Fprintf(&b, "opengfw_risk_events_total{severity=\"%s\"} %d\n",
			escapePromLabel(sample.Labels[0]), sample.Value)
	}
	return b.String()
}

func (m *metricsCollector) StartPacketIOStatsMonitor(ctx context.Context, config cliConfigMetrics) {
	if m == nil || m.packetIO == nil {
		return
	}
	interval := config.PacketStatsInterval
	if interval <= 0 {
		interval = defaultPacketStatsInterval
	}
	threshold := defaultPacketDropWarnRate
	if config.PacketDropWarnRate != nil {
		threshold = *config.PacketDropWarnRate
	}
	if threshold <= 0 {
		return
	}

	go func() {
		previous := m.packetIOStats()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			current := m.packetIOStats()
			packetDelta := saturatedSub(current.Packets, previous.Packets)
			dropDelta := saturatedSub(current.Drops, previous.Drops)
			losingDelta := saturatedSub(current.RingLosingBlocks, previous.RingLosingBlocks)
			previous = current
			if packetDelta == 0 && dropDelta == 0 && losingDelta == 0 {
				continue
			}
			dropRate := opengfwio.PacketIODropRate(packetDelta, dropDelta)
			if dropRate >= threshold || losingDelta > 0 {
				logger.Warn("packet IO kernel drops exceed threshold",
					zap.Uint64("packetDelta", packetDelta),
					zap.Uint64("dropDelta", dropDelta),
					zap.Float64("dropRate", dropRate),
					zap.Float64("threshold", threshold),
					zap.Uint64("ringLosingBlocksDelta", losingDelta),
					zap.Uint64("packetsTotal", current.Packets),
					zap.Uint64("dropsTotal", current.Drops),
					zap.Uint64("ringLosingBlocksTotal", current.RingLosingBlocks))
			}
		}
	}()
}

func saturatedSub(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func (m *metricsCollector) packetIOStats() opengfwio.PacketIOStats {
	if m == nil || m.packetIO == nil {
		return opengfwio.PacketIOStats{}
	}
	return m.packetIO.Stats()
}

func (m *metricsCollector) riskBucketCount() int {
	if m == nil || m.risk == nil {
		return 0
	}
	return m.risk.BucketCount()
}

type metricSample struct {
	Labels []string
	Value  uint64
}

func (c *labeledCounters1) Add(label string, delta uint64) {
	counter := c.counter(label)
	counter.value.Add(delta)
}

func (c *labeledCounters1) Samples() []metricSample {
	var samples []metricSample
	c.m.Range(func(key, value interface{}) bool {
		samples = append(samples, metricSample{
			Labels: []string{key.(string)},
			Value:  value.(*labeledCounter).value.Load(),
		})
		return true
	})
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].Labels[0] < samples[j].Labels[0]
	})
	return samples
}

func (c *labeledCounters1) counter(label string) *labeledCounter {
	value, _ := c.m.LoadOrStore(label, &labeledCounter{})
	return value.(*labeledCounter)
}

func (c *labeledCounters2) Add(label1, label2 string, delta uint64) {
	counter := c.counter(label1, label2)
	counter.value.Add(delta)
}

func (c *labeledCounters2) Samples() []metricSample {
	var samples []metricSample
	c.m.Range(func(key, value interface{}) bool {
		labels := splitMetricKey(key.(string))
		samples = append(samples, metricSample{
			Labels: labels,
			Value:  value.(*labeledCounter).value.Load(),
		})
		return true
	})
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Labels[0] == samples[j].Labels[0] {
			return samples[i].Labels[1] < samples[j].Labels[1]
		}
		return samples[i].Labels[0] < samples[j].Labels[0]
	})
	return samples
}

func (c *labeledCounters2) counter(label1, label2 string) *labeledCounter {
	value, _ := c.m.LoadOrStore(metricKey(label1, label2), &labeledCounter{})
	return value.(*labeledCounter)
}

func metricKey(labels ...string) string {
	escaped := make([]string, len(labels))
	for i, label := range labels {
		escaped[i] = strconv.Quote(label)
	}
	return strings.Join(escaped, "\xff")
}

func splitMetricKey(key string) []string {
	parts := strings.Split(key, "\xff")
	labels := make([]string, len(parts))
	for i, part := range parts {
		label, err := strconv.Unquote(part)
		if err != nil {
			label = part
		}
		labels[i] = label
	}
	return labels
}

func writeMetricHelp(b *strings.Builder, name, help string) {
	writeMetricHelpType(b, name, help, "counter")
}

func writeMetricHelpType(b *strings.Builder, name, help, metricType string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s %s\n", name, metricType)
}

func escapePromLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
