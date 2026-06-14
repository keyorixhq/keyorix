// Package notifychan implements external notification channels (ISO 27001 A.5.5 /
// SOC 2 — operational alerting): out-of-band delivery of the in-app notifications
// Keyorix already creates (approvals, anomalies, rotation/recertification reminders,
// break-glass) so they reach admins where they actually work, not just the header
// bell. Each channel implements core.NotificationSink.
//
// WebhookSink mirrors the SIEM audit forwarder: a bounded queue drained by a worker
// goroutine that POSTs the notification as JSON, so Deliver never blocks the
// triggering operation and a slow/0down endpoint drops rather than stalls.
package notifychan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
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
	cfg     WebhookConfig
	client  *http.Client
	queue   chan core.NotificationEvent
	wg      sync.WaitGroup
	mu      sync.Mutex
	dropped int
}

// NewWebhook builds a webhook sink and starts its delivery worker. The endpoint is
// required. The returned sink must be Close()d at shutdown to drain in-flight events.
func NewWebhook(cfg WebhookConfig) (*WebhookSink, error) {
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
		queue:  make(chan core.NotificationEvent, webhookQueueSize),
	}
	s.wg.Add(1)
	go s.worker()
	return s, nil
}

// Deliver enqueues the event for asynchronous POST. Non-blocking: if the queue is
// full (a wedged endpoint) the event is dropped and counted, never stalling the
// caller.
func (s *WebhookSink) Deliver(ev core.NotificationEvent) {
	if s == nil {
		return
	}
	select {
	case s.queue <- ev:
	default:
		s.mu.Lock()
		s.dropped++
		dropped := s.dropped
		s.mu.Unlock()
		log.Printf("notifychan: webhook queue full, dropped notification (total dropped: %d)", dropped)
	}
}

func (s *WebhookSink) worker() {
	defer s.wg.Done()
	for ev := range s.queue {
		if err := s.send(context.Background(), ev); err != nil {
			log.Printf("notifychan: webhook delivery failed: %v", err)
		}
	}
}

func (s *WebhookSink) send(ctx context.Context, ev core.NotificationEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook endpoint returned %s", strings.TrimSpace(resp.Status))
	}
	return nil
}

// Close stops the worker after draining queued events.
func (s *WebhookSink) Close() {
	if s == nil {
		return
	}
	close(s.queue)
	s.wg.Wait()
}
