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

const webhookTimeout = 30 * time.Second // the evidence pack can be large

// WebhookConfig configures the evidence webhook target.
type WebhookConfig struct {
	Endpoint           string // full destination URL (POST target)
	Token              string // optional bearer token
	InsecureSkipVerify bool   // skip TLS verification (self-signed only)
}

// Webhook POSTs the evidence pack JSON to an HTTP endpoint. Delivery is synchronous
// — it is only called from the once-a-day evidence scheduler, never a hot path.
type Webhook struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewWebhook builds an evidence webhook target. The endpoint is required.
func NewWebhook(cfg WebhookConfig) (*Webhook, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("evidencesink: webhook endpoint is required")
	}
	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in for self-signed endpoints
	}
	return &Webhook{cfg: cfg, client: &http.Client{Timeout: webhookTimeout, Transport: transport}}, nil
}

// ForwardEvidence POSTs the marshalled evidence pack as application/json.
func (w *Webhook) ForwardEvidence(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("evidence webhook endpoint returned %s", strings.TrimSpace(resp.Status))
	}
	return nil
}
