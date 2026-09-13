package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Alert represents a security or operational notification.
type Alert struct {
	ID            string    `json:"id"`
	Trigger       string    `json:"trigger"`
	Severity      string    `json:"severity"` // "normal", "critical"
	TableName     string    `json:"table_name"`
	RecordID      string    `json:"record_id,omitempty"`
	TransactionID string    `json:"transaction_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Message       string    `json:"message"`
	Acknowledged  bool      `json:"acknowledged"`
}

// AlertSink is the adapter interface for dispatching alerts.
type AlertSink interface {
	Send(ctx context.Context, alert Alert) error
}

// WebhookSink sends formatted alerts to a Discord or Telegram webhook URL.
type WebhookSink struct {
	webhookURL string
	httpClient *http.Client
}

// NewWebhookSink creates an alert webhook sink.
func NewWebhookSink(webhookURL string) *WebhookSink {
	return &WebhookSink{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Send formats and delivers an alert to the configured webhook endpoint.
func (s *WebhookSink) Send(ctx context.Context, alert Alert) error {
	if s.webhookURL == "" {
		return nil // No webhook configured, silent no-op
	}

	var content string
	if alert.Severity == "critical" {
		content = fmt.Sprintf("🚨 **@here [CRITICAL AUDIT ALERT]** 🚨\n**Table:** `%s`\n**Trigger:** %s\n**Message:** %s\n**Record ID:** `%s`\n**Transaction ID:** `%s`\n**Time:** %s",
			alert.TableName, alert.Trigger, alert.Message, alert.RecordID, alert.TransactionID, alert.Timestamp.Format(time.RFC3339))
	} else {
		content = fmt.Sprintf("⚠️ **[AUDIT ALERT - NORMAL]**\n**Table:** `%s`\n**Trigger:** %s\n**Message:** %s\n**Time:** %s",
			alert.TableName, alert.Trigger, alert.Message, alert.Timestamp.Format(time.RFC3339))
	}

	payload := map[string]string{
		"content": content,
		"text":    content, // for Telegram compatibility
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post alert webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with error status: %d", resp.StatusCode)
	}
	return nil
}

// MemorySink records alerts in memory for inspection, testing, and API querying.
type MemorySink struct {
	mu     sync.RWMutex
	alerts []Alert
}

// NewMemorySink creates a MemorySink.
func NewMemorySink() *MemorySink {
	return &MemorySink{
		alerts: make([]Alert, 0),
	}
}

// Send records an alert into the in-memory log.
func (m *MemorySink) Send(ctx context.Context, alert Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, alert)
	return nil
}

// GetAlerts returns a copy of all captured alerts.
func (m *MemorySink) GetAlerts() []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]Alert, len(m.alerts))
	copy(res, m.alerts)
	return res
}

// Acknowledge marks an alert as acknowledged by ID.
func (m *MemorySink) Acknowledge(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.alerts {
		if m.alerts[i].ID == id {
			m.alerts[i].Acknowledged = true
			return true
		}
	}
	return false
}

// Dispatcher coordinates rate limiting, sinks, and acknowledgment tracking.
type Dispatcher struct {
	mu          sync.Mutex
	sinks       []AlertSink
	memorySink  *MemorySink
	rateLimiter map[string]time.Time
	cooldown    time.Duration
}

// NewDispatcher creates an Alert Dispatcher.
func NewDispatcher(cooldown time.Duration, sinks ...AlertSink) *Dispatcher {
	memSink := NewMemorySink()
	allSinks := append([]AlertSink{memSink}, sinks...)
	return &Dispatcher{
		sinks:       allSinks,
		memorySink:  memSink,
		rateLimiter: make(map[string]time.Time),
		cooldown:    cooldown,
	}
}

// Trigger raises an alert through configured sinks with rate limiting.
func (d *Dispatcher) Trigger(ctx context.Context, trigger, severity, tableName, recordID, txID, message string) (*Alert, error) {
	d.mu.Lock()
	// Rate limit deduplication key: trigger:tableName
	rateKey := fmt.Sprintf("%s:%s", trigger, tableName)
	lastSent, exists := d.rateLimiter[rateKey]
	if exists && time.Since(lastSent) < d.cooldown {
		d.mu.Unlock()
		return nil, nil // Rate-limited suppressed duplicate
	}
	d.rateLimiter[rateKey] = time.Now()
	d.mu.Unlock()

	alert := Alert{
		ID:            uuid.New().String(),
		Trigger:       trigger,
		Severity:      severity,
		TableName:     tableName,
		RecordID:      recordID,
		TransactionID: txID,
		Timestamp:     time.Now().UTC(),
		Message:       message,
		Acknowledged:  false,
	}

	for _, sink := range d.sinks {
		_ = sink.Send(ctx, alert)
	}

	return &alert, nil
}

// MemorySink returns the underlying memory sink to query or acknowledge alerts.
func (d *Dispatcher) MemorySink() *MemorySink {
	return d.memorySink
}
