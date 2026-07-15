// Package siem forwards Keyorix audit events to external SIEM systems.
//
// It supports Splunk HEC, Datadog Logs intake, and a generic authenticated
// webhook. Forwarding is asynchronous and best-effort: Forward enqueues onto a
// bounded buffer and returns immediately, so a slow or unreachable SIEM never
// blocks or fails an audited operation. A small bounded pool of workers (see
// numWorkers) delivers concurrently, so an ordinary SLOW (not down) SIEM
// endpoint doesn't serialize the whole system's audit-forward throughput
// behind one request/response round trip. If the buffer is full, events are
// dropped (and counted, with the event's ID/type logged for forensic
// backfill) rather than applying backpressure to the request path.
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

// refuseRedirect blocks a redirect to a different host or an https->http downgrade.
// The SIEM auth rides in custom headers (DD-API-KEY, Splunk token) that Go does NOT
// strip on a cross-host redirect, so a compromised/misconfigured intake endpoint
// returning a 30x could otherwise bounce the credential-bearing request to an
// attacker-controlled or internal host (token exfil / SSRF).
func refuseRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if req.URL.Host != prev.URL.Host {
		return fmt.Errorf("siem: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("siem: refusing https->%s redirect", req.URL.Scheme)
	}
	return nil
}

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
	// SpoolDir, when set, enables a durable on-disk backlog: an event that would
	// otherwise be dropped (full queue) or fail after retries is persisted here and
	// replayed until the SIEM accepts it, so a sustained outage no longer silently
	// loses the off-box copy. Empty = best-effort only (the prior behaviour).
	SpoolDir string
}

// queueSize bounds in-flight events; httpTimeout bounds a single delivery.
const (
	queueSize   = 1024
	httpTimeout = 5 * time.Second
	// A transient failure (5xx/429/transport) is retried with exponential backoff so a
	// brief SIEM outage doesn't silently lose an audit event. 4 attempts at a 500ms
	// base ≈ 0.5s+1s+2s of backoff before giving up.
	maxAttempts        = 4
	defaultBaseBackoff = 500 * time.Millisecond
	// numWorkers bounds delivery concurrency (#199). A single strictly-serial worker
	// meant an ordinary SLOW (not even down) SIEM endpoint — worst case ~4 attempts x
	// 5s timeout + backoff, ≈23.5s per event — throttled the entire system's audit-
	// forward throughput to roughly one event per round trip, making silent
	// queue-overflow drops plausible under normal audited-API volume. A small bounded
	// pool multiplies throughput without letting a wedged endpoint spawn unbounded
	// concurrent connections.
	numWorkers = 4
)

// Forwarder ships audit events to a configured SIEM asynchronously.
type Forwarder struct {
	cfg         Config
	client      *http.Client
	queue       chan *models.AuditEvent
	baseBackoff time.Duration
	closing     chan struct{} // closed by Close to abort in-flight retry backoff
	closeOnce   sync.Once
	wg          sync.WaitGroup
	spool       *spool // nil unless Config.SpoolDir is set

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
	return newForwarder(cfg, defaultBaseBackoff)
}

// newForwarder is the constructor with an injectable retry backoff so tests don't
// sleep for real seconds. New is the production entry point.
func newForwarder(cfg Config, baseBackoff time.Duration) (*Forwarder, error) {
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
		log.Printf("WARNING: SIEM forwarder %q has TLS verification disabled (insecure_skip_verify); do not use in production", cfg.Endpoint)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- NOSONAR go:S4830 go:S5527: InsecureSkipVerify is an explicit operator opt-in, guarded by config flag and WARNING log
	}
	f := &Forwarder{
		cfg:         cfg,
		client:      &http.Client{Timeout: httpTimeout, Transport: transport, CheckRedirect: refuseRedirect},
		queue:       make(chan *models.AuditEvent, queueSize),
		baseBackoff: baseBackoff,
		closing:     make(chan struct{}),
	}
	if cfg.SpoolDir != "" {
		sp, serr := newSpool(cfg.SpoolDir, defaultReplayInterval, func(ctx context.Context, e *models.AuditEvent) error {
			_, err := f.send(ctx, e)
			return err
		})
		if serr != nil {
			return nil, serr
		}
		f.spool = sp
	}
	f.wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go f.worker()
	}
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
		// Queue full (a wedged/slow SIEM). Persist to the durable spool if configured so
		// the event is replayed later; otherwise fall back to a counted, logged drop.
		if f.spool != nil {
			f.spool.add(event)
			return
		}
		f.mu.Lock()
		f.dropped++
		dropped := f.dropped
		f.mu.Unlock()
		siemForwards.WithLabelValues(outcomeDropped).Inc()
		// Log the event's ID/EventType (matching the "failed" path's logging), not just
		// a running counter — without them a lost event can never be identified for
		// forensic backfill from the durable DB audit trail (#199).
		log.Printf("siem: audit forward queue full, dropped event %d (type %q, total dropped: %d)", event.ID, event.EventType, dropped)
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

// Close stops accepting events and waits for the in-flight queue to drain, abandoning
// any in-flight retry backoff so shutdown stays bounded. Idempotent.
func (f *Forwarder) Close() {
	if f == nil {
		return
	}
	f.closeOnce.Do(func() {
		close(f.closing)
		close(f.queue)
	})
	f.wg.Wait()
	f.spool.close() // nil-safe; stops the replay loop
}

func (f *Forwarder) worker() {
	defer f.wg.Done()
	for event := range f.queue {
		f.deliver(event)
	}
}

// deliver forwards one event, retrying transient failures with exponential backoff up
// to maxAttempts and recording the terminal outcome. A permanent failure (4xx) is not
// retried; backoff is abandoned promptly when closing so shutdown stays bounded.
func (f *Forwarder) deliver(event *models.AuditEvent) {
	backoff := f.baseBackoff
	for attempt := 1; ; attempt++ {
		retryable, err := f.send(context.Background(), event)
		if err == nil {
			siemForwards.WithLabelValues(outcomeDelivered).Inc()
			return
		}
		if !retryable || attempt >= maxAttempts {
			siemForwards.WithLabelValues(outcomeFailed).Inc()
			log.Printf("siem: failed to forward audit event %d after %d attempt(s): %v", event.ID, attempt, err)
			// Persist to the durable spool (if configured) so the off-box copy survives
			// a SIEM outage longer than the in-memory retry budget.
			if f.spool != nil {
				f.spool.add(event)
			}
			return
		}
		siemRetries.Inc()
		select {
		case <-time.After(backoff):
		case <-f.closing:
			siemForwards.WithLabelValues(outcomeFailed).Inc()
			log.Printf("siem: forward of audit event %d abandoned on shutdown after %d attempt(s): %v", event.ID, attempt, err)
			if f.spool != nil {
				f.spool.add(event)
			}
			return
		}
		backoff *= 2
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
	ActorType      string          `json:"actor_type,omitempty"`
	Success        bool            `json:"success"`
	Diff           json.RawMessage `json:"diff,omitempty"`
	Impersonation  bool            `json:"impersonation,omitempty"`
	ImpersonatedBy *uint           `json:"impersonated_by,omitempty"`
	ActingAs       *uint           `json:"acting_as,omitempty"`
	// Tamper-evidence chain links (ADR-029). Exporting them lets a downstream SIEM
	// re-link the chain and detect a dropped/forged/reordered event — without them an
	// export consumer cannot tell a gap (a lost event) from a contiguous stream.
	EntryHash string `json:"entry_hash,omitempty"`
	PrevHash  string `json:"prev_hash,omitempty"`
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
		ActorType:      e.ActorType,
		Success:        success,
		Impersonation:  e.Impersonation,
		ImpersonatedBy: e.ImpersonatedBy,
		ActingAs:       e.ActingAs,
		EntryHash:      e.EntryHash,
		PrevHash:       e.PrevHash,
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

// send forwards the event once. retryable reports whether a non-nil err is transient
// (a 5xx, 429, or transport/timeout error) and worth retrying; a 4xx or a payload-build
// error is permanent.
func (f *Forwarder) send(ctx context.Context, e *models.AuditEvent) (retryable bool, err error) {
	req, err := f.buildRequest(ctx, e)
	if err != nil {
		return false, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return true, err // transport / timeout — transient
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	retryable = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	return retryable, fmt.Errorf("siem endpoint returned %s", strings.TrimSpace(resp.Status))
}
