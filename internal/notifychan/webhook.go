// Package notifychan implements external notification channels (ISO 27001 A.5.5 /
// SOC 2 — operational alerting): out-of-band delivery of the in-app notifications
// Keyorix already creates (approvals, anomalies, rotation/recertification reminders,
// break-glass) so they reach admins where they actually work, not just the header
// bell. Each channel implements core.NotificationSink.
//
// Every sink shares the delivery engine in delivery.go: a bounded queue drained by a
// worker that sends one event at a time (so Deliver never blocks the triggering
// operation), retries transient failures with backoff, and records the outcome to
// Prometheus. A sink supplies only its own send func and a channel label.
package notifychan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	webhookTimeout   = 10 * time.Second
	webhookQueueSize = 256
)

// WebhookConfig configures the webhook notification channel.
type WebhookConfig struct {
	Endpoint           string // full destination URL (POST target)
	Token              string // optional bearer token (Authorization: Bearer <token>)
	InsecureSkipVerify bool   // skip TLS verification (test/self-signed only)
}

// WebhookSink delivers notifications to an HTTP endpoint as JSON, asynchronously.
type WebhookSink struct {
	cfg    WebhookConfig
	client *http.Client
	d      *deliverer
}

// NewWebhook builds a webhook sink and starts its delivery worker. The endpoint is
// required. The returned sink must be Close()d at shutdown to drain in-flight events.
func NewWebhook(cfg WebhookConfig) (*WebhookSink, error) {
	return newWebhook(cfg, deliveryBaseBackoff)
}

// newWebhook is the constructor with an injectable retry backoff so tests don't sleep
// for real seconds. NewWebhook is the production entry point.
func newWebhook(cfg WebhookConfig, baseBackoff time.Duration) (*WebhookSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("notifychan: webhook endpoint is required")
	}
	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in for self-signed endpoints
	}
	s := &WebhookSink{
		cfg:    cfg,
		client: &http.Client{Timeout: webhookTimeout, Transport: transport},
	}
	s.d = newDeliverer("webhook", webhookQueueSize, baseBackoff, s.send)
	return s, nil
}

// Deliver enqueues the event for asynchronous POST. Non-blocking: a full queue (a
// wedged endpoint) drops and counts the event rather than stalling the caller.
func (s *WebhookSink) Deliver(ev core.NotificationEvent) {
	if s == nil {
		return
	}
	s.d.enqueue(ev)
}

// send POSTs the event once. retryable reports whether a non-nil err is transient
// (a 5xx, 429, or transport/timeout error) and therefore worth retrying; a 4xx or a
// marshalling error is permanent.
func (s *WebhookSink) send(ctx context.Context, ev core.NotificationEvent) (retryable bool, err error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return false, fmt.Errorf("marshal notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return true, err // transport / timeout — transient
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	// 5xx and 429 are transient (endpoint overloaded / down); other 4xx are permanent
	// (bad request, auth) and won't succeed on retry.
	retryable = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	return retryable, fmt.Errorf("webhook endpoint returned %s", strings.TrimSpace(resp.Status))
}

// Close drains queued events and stops the worker, abandoning in-flight retry backoff
// so shutdown stays bounded. Idempotent.
func (s *WebhookSink) Close() {
	if s == nil {
		return
	}
	s.d.close()
}
