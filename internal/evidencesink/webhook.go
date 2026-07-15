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
	"log"
	"net"
	"net/http"
	"net/url"
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
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard — a
	// SEPARATE decision from InsecureSkipVerify (#130); see notifychan's
	// WebhookConfig.AllowPrivateNetworkTarget for the rationale.
	AllowPrivateNetworkTarget bool
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
	// Refuse a non-https (or internal-target) endpoint up front. Unlike the notification
	// webhook, this path previously sent the bearer token + the FULL compliance evidence
	// pack to whatever URL was configured — an http:// endpoint shipped both in cleartext
	// on every POST, and refuseRedirect only guards bounces, not the initial request.
	if err := validateEndpoint(cfg.Endpoint, cfg.AllowPrivateNetworkTarget); err != nil {
		return nil, err
	}
	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		log.Printf("WARNING: evidencesink webhook %q has TLS verification disabled (insecure_skip_verify); do not use in production", cfg.Endpoint)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- NOSONAR go:S4830 go:S5527: InsecureSkipVerify is an explicit operator opt-in
	}
	return &Webhook{cfg: cfg, client: &http.Client{Timeout: webhookTimeout, Transport: transport, CheckRedirect: refuseRedirect}, baseBackoff: baseBackoff}, nil
}

// validateEndpoint rejects a non-https evidence endpoint (which would send the bearer
// token and the full compliance pack in cleartext), allowing http only for a loopback
// target or the explicit allowPrivateNetwork opt-in. It also refuses a destination
// whose hostname RESOLVES to a private/link-local IP unless allowPrivateNetwork is
// set (SSRF/exfil hardening: an evidence pack must not be POSTed to cloud metadata or
// an internal host).
//
// allowPrivateNetwork is INTENTIONALLY separate from TLS-certificate verification
// (#130) — see notifychan's identically-named parameter for the rationale.
func validateEndpoint(raw string, allowPrivateNetwork bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("evidencesink: invalid endpoint %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		// scheme OK; fall through to the destination-IP check
	case "http":
		if !allowPrivateNetwork && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("evidencesink: endpoint %q must use https (set allow_private_network_target only for a trusted internal or loopback target)", raw)
		}
	default:
		return fmt.Errorf("evidencesink: endpoint %q must use https", raw)
	}
	if !allowPrivateNetwork {
		if err := refuseDisallowedHost(u.Hostname()); err != nil {
			return fmt.Errorf("evidencesink: endpoint %q %w", raw, err)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// lookupIPAddr resolves a hostname to its IP addresses — a var so tests can
// substitute a fake resolver without a real DNS query.
var lookupIPAddr = func(host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(context.Background(), host)
}

// refuseDisallowedHost rejects host when it — or any address it RESOLVES to — is a
// private, link-local, or otherwise disallowed IP (loopback permitted). A literal-
// IP-only check lets a hostname that resolves to an internal address straight
// through; this resolves the hostname and checks every returned address.
func refuseDisallowedHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("targets a private/link-local address; refusing to send evidence to an internal host")
		}
		return nil
	}
	addrs, err := lookupIPAddr(host)
	if err != nil {
		return fmt.Errorf("could not resolve hostname to verify it is not private/internal: %w", err)
	}
	for _, a := range addrs {
		if isDisallowedIP(a.IP) {
			return fmt.Errorf("resolves to a private/link-local address (%s); refusing to send evidence to an internal host", a.IP)
		}
	}
	return nil
}

// isDisallowedIP reports whether ip is a private or link-local address (loopback
// permitted).
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// refuseRedirect blocks a redirect to a different host or an https->http downgrade, so
// a compromised/misconfigured receiver returning a 30x cannot bounce the bearer-token-
// bearing evidence POST to an internal or cleartext target (SSRF / token exfil). The
// Authorization header is stripped by Go on a cross-host redirect, but the evidence pack
// itself (and a same-host downgrade) still warrant refusing the bounce outright.
func refuseRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if req.URL.Host != prev.URL.Host {
		return fmt.Errorf("evidencesink: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("evidencesink: refusing https->%s redirect", req.URL.Scheme)
	}
	return nil
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
