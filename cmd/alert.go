package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/apernet/OpenGFW/ruleset"

	"go.uber.org/zap"
)

const (
	defaultAlertQueueSize = 1024
	defaultAlertTimeout   = 3 * time.Second
)

type cliConfigAlert struct {
	WebhookURL string            `mapstructure:"webhookUrl"`
	QueueSize  int               `mapstructure:"queueSize"`
	Timeout    time.Duration     `mapstructure:"timeout"`
	Headers    map[string]string `mapstructure:"headers"`
}

type alertSink interface {
	Emit(alertEvent)
	Close()
}

type alertEvent struct {
	Type              string            `json:"type,omitempty"`
	Time              time.Time         `json:"time"`
	Rule              string            `json:"rule"`
	Severity          string            `json:"severity"`
	ID                int64             `json:"id"`
	Proto             string            `json:"proto"`
	Src               string            `json:"src"`
	Dst               string            `json:"dst"`
	IP                map[string]string `json:"ip"`
	Port              map[string]uint16 `json:"port"`
	Meta              map[string]string `json:"meta,omitempty"`
	Props             interface{}       `json:"props,omitempty"`
	Risk              *riskDetail       `json:"risk,omitempty"`
	Suppressed        bool              `json:"suppressed,omitempty"`
	SuppressionReason string            `json:"suppressionReason,omitempty"`
	SuppressionValue  string            `json:"suppressionValue,omitempty"`
}

type webhookAlertSink struct {
	url     string
	headers map[string]string
	client  *http.Client
	metrics *metricsCollector
	events  chan alertEvent
	stop    chan struct{}
	done    chan struct{}
}

func newAlertSink(config cliConfigAlert, dialContext func(context.Context, string, string) (net.Conn, error), metrics *metricsCollector) (alertSink, error) {
	if config.WebhookURL == "" {
		return nil, nil
	}
	if config.QueueSize <= 0 {
		config.QueueSize = defaultAlertQueueSize
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultAlertTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if dialContext != nil {
		transport.DialContext = dialContext
	}

	s := &webhookAlertSink{
		url:     config.WebhookURL,
		headers: config.Headers,
		metrics: metrics,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		events: make(chan alertEvent, config.QueueSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go s.run()
	return s, nil
}

func newAlertEvent(info ruleset.StreamInfo, name string, metadata ruleset.MatchMetadata) alertEvent {
	return alertEvent{
		Time:     time.Now().UTC(),
		Rule:     name,
		Severity: metadata.Severity,
		ID:       info.ID,
		Proto:    info.Protocol.String(),
		Src:      info.SrcString(),
		Dst:      info.DstString(),
		IP: map[string]string{
			"src": info.SrcIP.String(),
			"dst": info.DstIP.String(),
		},
		Port: map[string]uint16{
			"src": info.SrcPort,
			"dst": info.DstPort,
		},
		Meta:  info.Meta,
		Props: info.Props,
	}
}

func (s *webhookAlertSink) Emit(event alertEvent) {
	select {
	case s.events <- event:
	case <-s.stop:
	default:
		s.metrics.IncAlertDropped()
		logger.Warn("alert queue full, dropping event",
			zap.String("rule", event.Rule),
			zap.Int64("id", event.ID))
	}
}

func (s *webhookAlertSink) Close() {
	close(s.stop)
	<-s.done
}

func (s *webhookAlertSink) run() {
	defer close(s.done)
	for {
		select {
		case event := <-s.events:
			if err := s.post(event); err != nil {
				logger.Warn("failed to send alert",
					zap.String("rule", event.Rule),
					zap.Int64("id", event.ID),
					zap.Error(err))
			}
		case <-s.stop:
			return
		}
	}
}

func (s *webhookAlertSink) post(event alertEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warn("alert webhook returned non-2xx status",
			zap.Int("status", resp.StatusCode),
			zap.String("rule", event.Rule),
			zap.Int64("id", event.ID))
	}
	return nil
}
