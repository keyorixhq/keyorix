package notary

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/digitorus/timestamp"
)

// defaultTimeout bounds the round-trip to the timestamp authority.
const defaultTimeout = 15 * time.Second

// maxResponseBytes caps how much of the TSA reply we read — a timestamp response
// is a few KB; this guards against a misbehaving/hostile endpoint.
const maxResponseBytes = 1 << 20 // 1 MiB

// RFC3161 anchors a message with an RFC 3161 Time-Stamp Authority (TSA): it POSTs
// a SHA-256 MessageImprint over the message and stores the returned signed
// TimeStampToken as the receipt. Credentials/TLS come from the standard HTTP
// client; the URL is operator-configured deployment config.
type RFC3161 struct {
	url    string
	client *http.Client
}

// NewRFC3161 builds a TSA notary for the given query URL. A non-positive timeout
// falls back to defaultTimeout. Returns an error if url is not an https URL (or
// http to a loopback host, for local testing — see validateTSAURL) so a
// misconfigured plaintext TSA is caught at startup, not on the first anchor
// attempt.
func NewRFC3161(url string, timeout time.Duration) (*RFC3161, error) {
	if err := validateTSAURL(url); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &RFC3161{url: url, client: &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect}}, nil
}

// refuseRedirect stops the TSA client from following any redirect: without this,
// a 3xx response from a compromised/misconfigured TSA endpoint could bounce the
// request to an internal host (e.g. cloud IMDS) even though the configured URL
// itself was fine at setup time (CWE-918).
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("rfc3161: refusing to follow redirect to %q", req.URL)
}

func (r *RFC3161) Provider() string { return "rfc3161:" + r.url }

// validateTSAURL checks that the configured TSA URL is a well-formed absolute
// URL using https. Plaintext http is accepted ONLY to a loopback host
// (localhost/127.0.0.1/::1), for local development/testing — the same
// exception this codebase uses for other operator-configured outbound URLs
// (internal/storage/remote/config.go's validateBaseURL, server/main.go's
// requireSecureOrLoopback). A non-loopback http:// TSA URL is rejected: the
// TSA response itself is a signed token, but the request leg (the checkpoint
// hash being timestamped, plus the response in transit) still needs transport
// confidentiality/integrity — a network attacker on a plaintext path can see
// every checkpoint being anchored and swap in a rogue TSA's response, and
// nothing else in this codebase distinguishes "recorded" from "meaningfully
// anchored" for the operator relying on this feature.
func validateTSAURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("rfc3161: invalid url %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("rfc3161: url %q is missing a host", raw)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return fmt.Errorf("rfc3161: url %q must use https (http is allowed only for a loopback host, for local testing)", raw)
	}
	return nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP — mirrors
// the same helper this codebase uses elsewhere for outbound-URL TLS checks.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (r *RFC3161) Anchor(ctx context.Context, message []byte) (_ *Receipt, err error) {
	if err := validateTSAURL(r.url); err != nil {
		return nil, err
	}
	// #G61: digitorus/pkcs7 panics on certain malformed BER inputs instead of
	// returning an error (index out of range in ber.go:readObject, found by
	// fuzz rig) — the same known parser panic class notary.go's VerifyReceipt
	// was already hardened against. ParseResponse below hands attacker/TSA-
	// controlled bytes to that same parser, so this needs the identical
	// recover(): a hostile or buggy TSA endpoint must return an error, not
	// crash the process anchoring an audit checkpoint.
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("rfc3161: parser panic on malformed TSA response: %v", rec)
		}
	}()
	// CreateRequest hashes the message (SHA-256) into the MessageImprint and asks
	// the TSA to include its signing certificate so the token is self-contained.
	reqDER, err := timestamp.CreateRequest(bytes.NewReader(message), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("rfc3161: build request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: post to %s: %w", r.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rfc3161: %s returned HTTP %d", r.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: read response: %w", err)
	}

	// ParseResponse validates the PKI status and the token's signature structure.
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: parse response: %w", err)
	}
	return &Receipt{Token: ts.RawToken, Time: ts.Time, Provider: r.Provider()}, nil
}
