// Package siem forwards Keyorix audit events to external SIEM systems.
//
// It supports Splunk HEC, Datadog Logs intake, and a generic authenticated
// webhook. Forwarding is asynchronous and best-effort: Forward enqueues onto a
// bounded buffer and returns immediately, so a slow or unreachable SIEM never
// blocks or fails an audited operation. If the buffer is full, events are
// dropped (and counted) rather than applying backpressure to the request path.
//
// SECURITY: audit events carry no plaintext secret values (the value diff is a
// {"changed":true} marker only — see internal/core/audit_diff.go), so an audit
// payload is safe to ship off-box.
package siem

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

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Provider identifies the destination SIEM format.
type Provider string

const (
	ProviderSplunk  Provider = "splunk"
	ProviderDatadog Provider = "datadog"
	ProviderWebhook Provider = "webhook"
)

// Config configures a Forwarder.
type Config struct {
	Enabled            bool
	Provider           Provider
	Endpoint           string // full destination URL (e.g. Splunk HEC collector URL)
	Token              string // HEC token / DD-API-KEY / bearer token
	InsecureSkipVerify bool   // skip TLS verification (self-signed SIEM endpoints)
}

// queueSize bounds in-flight events; httpTimeout bounds a single delivery.
const (
	queueSize   = 1024
	httpTimeout = 5 * time.Second
)

// Forwarder ships audit events to a configured SIEM asynchronously.
type Forwarder struct {
	cfg    Config
	client *http.Client
	queue  chan *models.AuditEvent
	wg     sync.WaitGroup

	mu      sync.Mutex
	dropped int64
}

// New validates cfg and starts the background delivery worker. It returns
// (nil, nil) when SIEM forwarding is disabled, so callers can wire it
// unconditionally.
func New(cfg Config) (*Forwarder, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("siem: endpoint is required when enabled")
	}
	switch cfg.Provider {
	case ProviderSplunk, ProviderDatadog, ProviderWebhook:
	default:
		return nil, fmt.Errorf("siem: unknown provider %q (want splunk|datadog|webhook)", cfg.Provider)
	}

	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — operator opt-in for self-signed SIEM
	}
	f := &Forwarder{
		cfg:    cfg,
		client: &http.Client{Timeout: httpTimeout, Transport: transport},
		queue:  make(chan *models.AuditEvent, queueSize),
	}
	f.wg.Add(1)
	go f.worker()
	return f, nil
}

// Forward enqueues an event for delivery. Non-blocking: if the buffer is full
// the event is dropped and counted (Dropped), never blocking the caller.
func (f *Forwarder) Forward(event *models.AuditEvent) {
	if f == nil || event == nil {
		return
	}
	select {
	case f.queue <- event:
	default:
		f.mu.Lock()
		f.dropped++
		dropped := f.dropped
		f.mu.Unlock()
		log.Printf("siem: audit forward queue full, dropped event (total dropped: %d)", dropped)
	}
}

// Dropped returns the number of events dropped due to a full queue.
func (f *Forwarder) Dropped() int64 {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped
}

// Close stops accepting events and waits for the in-flight queue to drain.
func (f *Forwarder) Close() {
	if f == nil {
		return
	}
	close(f.queue)
	f.wg.Wait()
}

func (f *Forwarder) worker() {
	defer f.wg.Done()
	for event := range f.queue {
		if err := f.send(context.Background(), event); err != nil {
			log.Printf("siem: failed to forward audit event %d: %v", event.ID, err)
		}
	}
}

// eventPayload is the stable, snake_case wire shape sent to SIEMs. AuditEvent
// has no JSON tags, so we never marshal the model directly.
type eventPayload struct {
	ID             uint            `json:"id"`
	EventType      string          `json:"event_type"`
	Timestamp      string          `json:"timestamp"`
	UserID         *uint           `json:"user_id,omitempty"`
	ProjectID      *uint           `json:"project_id,omitempty"`
	SecretID       *uint           `json:"secret_id,omitempty"`
	Description    string          `json:"description"`
	IPAddress      string          `json:"ip_address,omitempty"`
	Success        bool            `json:"success"`
	Diff           json.RawMessage `json:"diff,omitempty"`
	Impersonation  bool            `json:"impersonation,omitempty"`
	ImpersonatedBy *uint           `json:"impersonated_by,omitempty"`
	ActingAs       *uint           `json:"acting_as,omitempty"`
}

func toPayload(e *models.AuditEvent) eventPayload {
	success := true
	if e.Success != nil {
		success = *e.Success
	}
	p := eventPayload{
		ID:             e.ID,
		EventType:      e.EventType,
		Timestamp:      e.EventTime.UTC().Format(time.RFC3339),
		UserID:         e.UserID,
		ProjectID:      e.ProjectID,
		SecretID:       e.SecretNodeID,
		Description:    e.Description,
		IPAddress:      e.IPAddress,
		Success:        success,
		Impersonation:  e.Impersonation,
		ImpersonatedBy: e.ImpersonatedBy,
		ActingAs:       e.ActingAs,
	}
	if e.Diff != "" {
		p.Diff = json.RawMessage(e.Diff)
	}
	return p
}

// buildRequest produces the provider-specific HTTP request body + headers.
func (f *Forwarder) buildRequest(ctx context.Context, e *models.AuditEvent) (*http.Request, error) {
	payload := toPayload(e)
	var body []byte
	var err error
	headers := map[string]string{"Content-Type": "application/json"}

	switch f.cfg.Provider {
	case ProviderSplunk:
		// Splunk HEC event envelope.
		body, err = json.Marshal(map[string]any{
			"time":       e.EventTime.UTC().Unix(),
			"source":     "keyorix",
			"sourcetype": "keyorix:audit",
			"event":      payload,
		})
		headers["Authorization"] = "Splunk " + f.cfg.Token
	case ProviderDatadog:
		// Datadog Logs intake: enrich with ddsource/service for routing.
		body, err = json.Marshal(map[string]any{
			"ddsource": "keyorix",
			"service":  "keyorix",
			"message":  e.Description,
			"audit":    payload,
		})
		headers["DD-API-KEY"] = f.cfg.Token
	default: // webhook
		body, err = json.Marshal(payload)
		if f.cfg.Token != "" {
			headers["Authorization"] = "Bearer " + f.cfg.Token
		}
	}
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (f *Forwarder) send(ctx context.Context, e *models.AuditEvent) error {
	req, err := f.buildRequest(ctx, e)
	if err != nil {
		return err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem endpoint returned %s", strings.TrimSpace(resp.Status))
	}
	return nil
}
