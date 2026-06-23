// Package evidencesink implements off-box delivery targets for the scheduled
// compliance-evidence pack (ISO 27001 / SOC 2 continuous evidence), beyond the
// local output directory: a webhook that POSTs the pack so evidence survives the
// node without a mounted volume. Implements core.EvidenceForwarder.
package evidencesink

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	webhookTimeout = 30 * time.Second // the evidence pack can be large
	// A transient failure (5xx/429/transport) is retried with exponential backoff so a
	// brief receiver outage doesn't lose a day's evidence pack until the next run.
	maxAttempts        = 4
	defaultBaseBackoff = 1 * time.Second
)

// WebhookConfig configures the evidence webhook target.
type WebhookConfig struct {
	Endpoint           string // full destination URL (POST target)
	Token              string // optional bearer token
	InsecureSkipVerify bool   // skip TLS verification (self-signed only)
}

// Webhook POSTs the evidence pack JSON to an HTTP endpoint. Delivery is synchronous
// — it is only called from the once-a-day evidence scheduler, never a hot path — so it
// retries transient failures in-call rather than queueing.
type Webhook struct {
	cfg         WebhookConfig
	client      *http.Client
	baseBackoff time.Duration
}

// NewWebhook builds an evidence webhook target. The endpoint is required.
func NewWebhook(cfg WebhookConfig) (*Webhook, error) {
	return newWebhook(cfg, defaultBaseBackoff)
}

// newWebhook is the constructor with an injectable retry backoff so tests don't sleep
// for real seconds. NewWebhook is the production entry point.
func newWebhook(cfg WebhookConfig, baseBackoff time.Duration) (*Webhook, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("evidencesink: webhook endpoint is required")
	}
	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in for self-signed endpoints
	}
	return &Webhook{cfg: cfg, client: &http.Client{Timeout: webhookTimeout, Transport: transport}, baseBackoff: baseBackoff}, nil
}

// ForwardEvidence POSTs the marshalled evidence pack as application/json. The pack's
// canonical name rides in X-Keyorix-Evidence-Filename, and when the pack is signed
// the detached HMAC signature is sent in X-Keyorix-Evidence-Signature so the receiver
// can record both for later verification.
//
// Transient failures (5xx, 429, transport/timeout) are retried with exponential
// backoff up to maxAttempts; a 4xx is permanent and returned immediately. Backoff
// respects ctx cancellation so a shutdown isn't extended.
func (w *Webhook) ForwardEvidence(ctx context.Context, name string, data []byte, signature string) error {
	backoff := w.baseBackoff
	for attempt := 1; ; attempt++ {
		retryable, err := w.post(ctx, name, data, signature)
		if err == nil {
			return nil
		}
		if !retryable || attempt >= maxAttempts {
			return err
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return fmt.Errorf("evidence webhook delivery cancelled after %d attempt(s): %w", attempt, ctx.Err())
		}
		backoff *= 2
	}
}

// post sends the pack once. retryable reports whether a non-nil err is transient
// (a 5xx, 429, or transport/timeout error) versus permanent (a 4xx or build error).
func (w *Webhook) post(ctx context.Context, name string, data []byte, signature string) (retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if name != "" {
		req.Header.Set("X-Keyorix-Evidence-Filename", name)
	}
	if signature != "" {
		req.Header.Set("X-Keyorix-Evidence-Signature", signature)
	}
	if w.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return true, err // transport / timeout — transient
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	retryable = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	return retryable, fmt.Errorf("evidence webhook endpoint returned %s", strings.TrimSpace(resp.Status))
}

// Target labels this forwarder in the export result.
func (w *Webhook) Target() string { return "webhook" }
