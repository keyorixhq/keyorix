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
	// A transient failure (5xx/429/transport error) is retried with exponential
	// backoff so a brief endpoint blip doesn't silently lose an operational alert.
	// 4 attempts at a 500ms base ≈ 0.5s+1s+2s of backoff before giving up.
	webhookMaxAttempts = 4
	webhookBaseBackoff = 500 * time.Millisecond
)

// WebhookConfig configures the webhook notification channel.
type WebhookConfig struct {
	Endpoint           string // full destination URL (POST target)
	Token              string // optional bearer token (Authorization: Bearer <token>)
	InsecureSkipVerify bool   // skip TLS verification (test/self-signed only)
}

// WebhookSink delivers notifications to an HTTP endpoint as JSON, asynchronously.
type WebhookSink struct {
	cfg         WebhookConfig
	client      *http.Client
	queue       chan core.NotificationEvent
	baseBackoff time.Duration
	closing     chan struct{} // closed by Close to abort in-flight retry backoff
	closeOnce   sync.Once
	wg          sync.WaitGroup
	mu          sync.Mutex
	dropped     int
}

// NewWebhook builds a webhook sink and starts its delivery worker. The endpoint is
// required. The returned sink must be Close()d at shutdown to drain in-flight events.
func NewWebhook(cfg WebhookConfig) (*WebhookSink, error) {
	return newWebhook(cfg, webhookBaseBackoff)
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
		cfg:         cfg,
		client:      &http.Client{Timeout: webhookTimeout, Transport: transport},
		queue:       make(chan core.NotificationEvent, webhookQueueSize),
		baseBackoff: baseBackoff,
		closing:     make(chan struct{}),
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
		webhookDeliveries.WithLabelValues(outcomeDropped).Inc()
		log.Printf("notifychan: webhook queue full, dropped notification (total dropped: %d)", dropped)
	}
}

func (s *WebhookSink) worker() {
	defer s.wg.Done()
	for ev := range s.queue {
		s.deliver(ev)
	}
}

// deliver POSTs the event, retrying transient failures with exponential backoff up to
// webhookMaxAttempts. A permanent failure (4xx) is not retried; backoff is abandoned
// promptly if the sink is closing so shutdown isn't extended by retries. Records the
// terminal outcome to Prometheus.
func (s *WebhookSink) deliver(ev core.NotificationEvent) {
	backoff := s.baseBackoff
	for attempt := 1; ; attempt++ {
		retryable, err := s.send(context.Background(), ev)
		if err == nil {
			webhookDeliveries.WithLabelValues(outcomeDelivered).Inc()
			return
		}
		if !retryable || attempt >= webhookMaxAttempts {
			webhookDeliveries.WithLabelValues(outcomeFailed).Inc()
			log.Printf("notifychan: webhook delivery failed after %d attempt(s): %v", attempt, err)
			return
		}
		webhookRetries.Inc()
		select {
		case <-time.After(backoff):
		case <-s.closing:
			// Shutting down — don't extend Close() with retry backoff.
			webhookDeliveries.WithLabelValues(outcomeFailed).Inc()
			log.Printf("notifychan: webhook delivery abandoned on shutdown after %d attempt(s): %v", attempt, err)
			return
		}
		backoff *= 2
	}
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

// Close stops the worker after draining queued events, abandoning any in-flight retry
// backoff so shutdown stays bounded. Idempotent.
func (s *WebhookSink) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.closing)
		close(s.queue)
	})
	s.wg.Wait()
}
