package cmd

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

const defaultRiskWindow = 10 * time.Minute

type cliConfigRisk struct {
	Enabled    bool                    `mapstructure:"enabled"`
	Window     time.Duration           `mapstructure:"window"`
	Thresholds cliConfigRiskThresholds `mapstructure:"thresholds"`
	Weights    map[string]int          `mapstructure:"weights"`
}

type cliConfigRiskThresholds struct {
	Alert    int `mapstructure:"alert"`
	Response int `mapstructure:"response"`
}

type riskAggregator struct {
	window            time.Duration
	alertThreshold    int
	responseThreshold int
	weights           map[string]int
	alert             alertSink
	response          responseSink
	metrics           *metricsCollector
	now               func() time.Time

	mu      sync.Mutex
	buckets map[string]*riskBucket
}

type riskBucket struct {
	Key          string
	KeyType      string
	Hits         []riskHit
	Score        int
	AlertSent    bool
	ResponseSent bool
}

type riskHit struct {
	Time     time.Time `json:"time"`
	Rule     string    `json:"rule"`
	Severity string    `json:"severity,omitempty"`
	ID       int64     `json:"id"`
	Weight   int       `json:"weight"`
}

type riskDetail struct {
	Key               string    `json:"key"`
	KeyType           string    `json:"keyType"`
	Score             int       `json:"score"`
	WindowSeconds     int       `json:"windowSeconds"`
	AlertThreshold    int       `json:"alertThreshold,omitempty"`
	ResponseThreshold int       `json:"responseThreshold,omitempty"`
	Hits              []riskHit `json:"hits"`
}

func newRiskAggregator(config cliConfigRisk, alert alertSink, response responseSink) (*riskAggregator, error) {
	if !config.Enabled {
		return nil, nil
	}
	if config.Window <= 0 {
		config.Window = defaultRiskWindow
	}
	if config.Thresholds.Alert <= 0 && config.Thresholds.Response <= 0 {
		return nil, errors.New("risk.thresholds.alert or risk.thresholds.response is required when risk.enabled is true")
	}
	return &riskAggregator{
		window:            config.Window,
		alertThreshold:    config.Thresholds.Alert,
		responseThreshold: config.Thresholds.Response,
		weights:           config.Weights,
		alert:             alert,
		response:          response,
		now:               time.Now,
		buckets:           make(map[string]*riskBucket),
	}, nil
}

func (r *riskAggregator) Add(event alertEvent) {
	if r == nil {
		return
	}
	keyType, key := riskAggregationKey(event)
	if key == "" {
		if logger != nil {
			logger.Debug("risk event has no aggregation key",
				zap.String("rule", event.Rule),
				zap.Int64("id", event.ID))
		}
		return
	}
	weight := r.ruleWeight(event.Rule)
	if weight <= 0 {
		return
	}

	now := r.now().UTC()
	event.Time = now

	var riskEvent alertEvent
	alertCrossed := false
	responseCrossed := false

	r.mu.Lock()
	bucket := r.bucket(keyType, key)
	r.prune(bucket, now)
	if r.alertThreshold > 0 && bucket.Score < r.alertThreshold {
		bucket.AlertSent = false
	}
	if r.responseThreshold > 0 && bucket.Score < r.responseThreshold {
		bucket.ResponseSent = false
	}

	bucket.Hits = append(bucket.Hits, riskHit{
		Time:     now,
		Rule:     event.Rule,
		Severity: event.Severity,
		ID:       event.ID,
		Weight:   weight,
	})
	bucket.Score += weight

	alertCrossed = r.alertThreshold > 0 && bucket.Score >= r.alertThreshold && !bucket.AlertSent
	responseCrossed = r.responseThreshold > 0 && bucket.Score >= r.responseThreshold && !bucket.ResponseSent
	if alertCrossed {
		bucket.AlertSent = true
	}
	if responseCrossed {
		bucket.ResponseSent = true
	}
	if alertCrossed || responseCrossed {
		riskEvent = newRiskEvent(event, bucket, r.window, r.alertThreshold, r.responseThreshold)
	}
	r.mu.Unlock()

	if (alertCrossed || responseCrossed) && r.metrics != nil {
		r.metrics.IncRiskEvent(riskEvent.Severity)
	}
	if alertCrossed && r.alert != nil {
		r.alert.Emit(riskEvent)
	}
	if responseCrossed && r.response != nil {
		r.response.Quarantine(riskEvent)
	}
}

func (r *riskAggregator) bucket(keyType, key string) *riskBucket {
	bucketID := keyType + "\x00" + key
	bucket, ok := r.buckets[bucketID]
	if ok {
		return bucket
	}
	bucket = &riskBucket{
		Key:     key,
		KeyType: keyType,
	}
	r.buckets[bucketID] = bucket
	return bucket
}

func (r *riskAggregator) prune(bucket *riskBucket, now time.Time) {
	cutoff := now.Add(-r.window)
	kept := bucket.Hits[:0]
	score := 0
	for _, hit := range bucket.Hits {
		if hit.Time.Before(cutoff) {
			continue
		}
		kept = append(kept, hit)
		score += hit.Weight
	}
	bucket.Hits = kept
	bucket.Score = score
}

func (r *riskAggregator) BucketCount() int {
	if r == nil {
		return 0
	}
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, bucket := range r.buckets {
		r.prune(bucket, now)
		if len(bucket.Hits) == 0 {
			delete(r.buckets, id)
		}
	}
	return len(r.buckets)
}

func (r *riskAggregator) ruleWeight(rule string) int {
	if r.weights == nil {
		return 1
	}
	if weight, ok := r.weights[rule]; ok {
		return weight
	}
	return 1
}

func riskAggregationKey(event alertEvent) (string, string) {
	if value := event.Meta["vm.id"]; value != "" {
		return "vm.id", value
	}
	if value := normalizeMAC(event.Meta["vm.mac"]); value != "" {
		return "vm.mac", value
	}
	if event.IP != nil {
		if value := event.IP["src"]; value != "" && value != "<nil>" {
			return "ip.src", value
		}
	}
	return "", ""
}

func newRiskEvent(base alertEvent, bucket *riskBucket, window time.Duration, alertThreshold, responseThreshold int) alertEvent {
	hits := append([]riskHit(nil), bucket.Hits...)
	score := bucket.Score
	severity := "medium"
	if responseThreshold > 0 && score >= responseThreshold {
		severity = "high"
	}
	event := base
	event.Type = "risk"
	event.Rule = "risk"
	event.Severity = severity
	event.Risk = &riskDetail{
		Key:               bucket.Key,
		KeyType:           bucket.KeyType,
		Score:             score,
		WindowSeconds:     durationSeconds(window),
		AlertThreshold:    alertThreshold,
		ResponseThreshold: responseThreshold,
		Hits:              hits,
	}
	if event.Meta == nil {
		event.Meta = make(map[string]string)
	}
	event.Meta = copyStringMap(event.Meta)
	event.Meta["risk.key"] = bucket.Key
	event.Meta["risk.key_type"] = bucket.KeyType
	event.Meta["risk.score"] = strconv.Itoa(score)
	return event
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
