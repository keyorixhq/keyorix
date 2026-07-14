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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard (a literal
	// or DNS-resolved private/link-local destination is refused by default) — a
	// SEPARATE decision from InsecureSkipVerify (#130): trusting a self-signed cert
	// doesn't mean the endpoint should be allowed to live on an internal network,
	// and a legitimate on-prem receiver with a real cert still needs this to reach
	// its private address.
	AllowPrivateNetworkTarget bool
	// SigningSecret, when set, signs each payload with HMAC-SHA256 so the receiver can
	// verify it came from Keyorix: header X-Keyorix-Signature: sha256=<hex(hmac(body))>.
	SigningSecret string
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
	if err := validateEndpoint(cfg.Endpoint, cfg.AllowPrivateNetworkTarget); err != nil {
		return nil, err
	}
	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		log.Printf("WARNING: notifychan webhook %q has TLS verification disabled (insecure_skip_verify); do not use in production", cfg.Endpoint)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in for self-signed endpoints NOSONAR
	}
	s := &WebhookSink{
		cfg:    cfg,
		client: &http.Client{Timeout: webhookTimeout, Transport: transport, CheckRedirect: refuseRedirectDowngrade},
	}
	s.d = newDeliverer("webhook", webhookQueueSize, baseBackoff, s.send)
	return s, nil
}

// Deliver enqueues the event for asynchronous POST. Non-blocking: a full queue (a
// wedged endpoint) drops and counts the event rather than stalling the caller. The
// webhook endpoint is one fixed, operator-configured destination — not a per-user
// address — so every event (including a broadcast) is always attempted; Deliver
// only reports false when the sink itself is nil.
func (s *WebhookSink) Deliver(ev core.NotificationEvent) bool {
	if s == nil {
		return false
	}
	s.d.enqueue(ev)
	return true
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
	if s.cfg.SigningSecret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.SigningSecret))
		mac.Write(body)
		req.Header.Set("X-Keyorix-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
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
