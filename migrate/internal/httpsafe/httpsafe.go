// Package httpsafe holds the small set of HTTP hardening primitives every cloud-source client
// in this module needs: a redirect refusal and a response-size cap. This is a deliberate,
// migrate-owned COPY of the same safeguards internal/connect/hardened_client.go already applies
// to the server's own AWS/Azure connectors — migrate cannot import internal/connect (module
// boundary, docs/design-keyorix-migrate.md's "Module boundaries" section), so the logic is
// ported, not shared, matching vaultsource's own precedent of carrying these two safeguards
// forward unchanged rather than weakening them for this tool.
package httpsafe

import (
	"io"
	"net/http"
	"time"
)

// ClientTimeout bounds every request a cloud-source client makes, matching vaultsource's
// clientTimeout precedent.
const ClientTimeout = 30 * time.Second

// MaxResponseBytes caps how much of a single HTTP response body a cloud-source client reads
// into memory, matching vaultsource's maxResponseBytes precedent — generous enough for a large
// secret value, still bounded against a malicious or misbehaving endpoint.
const MaxResponseBytes = 10 << 20 // 10MB

// RefuseRedirect matches vaultsource's CheckRedirect: a credential-bearing request must never
// follow a redirect to a host the operator did not configure.
func RefuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// CappedTransport wraps Base, limiting every response body read to MaxResponseBytes — a
// malicious or compromised cloud endpoint must not be able to force this process to buffer an
// unbounded body before the SDK on top of it ever gets a chance to reject it.
type CappedTransport struct {
	Base http.RoundTripper
}

func (t CappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	resp.Body = &cappedReadCloser{r: io.LimitReader(resp.Body, MaxResponseBytes), c: resp.Body}
	return resp, nil
}

// cappedReadCloser pairs a size-limited Reader with the original response body's Close, so the
// underlying connection is still released normally.
type cappedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *cappedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *cappedReadCloser) Close() error               { return l.c.Close() }

// Client builds an *http.Client with the redirect refusal and response cap applied — the
// standard shape every cloud-source package's client() constructor uses.
func Client() *http.Client {
	return &http.Client{
		Timeout:       ClientTimeout,
		Transport:     CappedTransport{Base: http.DefaultTransport},
		CheckRedirect: RefuseRedirect,
	}
}
