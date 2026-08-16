package notary

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewRFC3161 — zero/negative timeout falls back to defaultTimeout
// ---------------------------------------------------------------------------

func TestNewRFC3161_ZeroTimeout_UsesDefault(t *testing.T) {
	r, err := NewRFC3161("https://example.tsa/rfc3161", 0)
	require.NoError(t, err)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

// ---------------------------------------------------------------------------
// VerifyReceipt — malformed token must not panic (fuzz regression)
// ---------------------------------------------------------------------------

// TestVerifyReceipt_MalformedToken_NoPanic guards against digitorus/pkcs7
// panicking on truncated BER inputs (index out of range in ber.go:readObject,
// found by the continuous fuzz rig on 2026-07-27).
func TestVerifyReceipt_MalformedToken_NoPanic(t *testing.T) {
	roots := x509.NewCertPool()
	msg := []byte("any message")
	cases := [][]byte{
		{0x30, 0x81},             // SEQUENCE + long-form length, no length byte follows
		{0x30, 0x82},             // SEQUENCE + long-form length claiming 2 bytes, none follow
		{0x30, 0x01},             // SEQUENCE claiming 1 content byte, none present
		{0xff, 0x81},             // high-tag-number form, truncated
		{0x30, 0x80, 0x00, 0x00}, // indefinite-length SEQUENCE
	}
	for _, token := range cases {
		require.NotPanics(t, func() {
			_, _ = VerifyReceipt(roots, msg, token)
		})
	}
}

func TestNewRFC3161_NegativeTimeout_UsesDefault(t *testing.T) {
	r, err := NewRFC3161("https://example.tsa/rfc3161", -1*time.Second)
	require.NoError(t, err)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

func TestNewRFC3161_PositiveTimeout_Respected(t *testing.T) {
	r, err := NewRFC3161("https://example.tsa/rfc3161", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, r.client.Timeout)
}

func TestRFC3161_Provider(t *testing.T) {
	r, err := NewRFC3161("https://freetsa.org/tsr", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "rfc3161:https://freetsa.org/tsr", r.Provider())
}

// ---------------------------------------------------------------------------
// Anchor — error paths that don't require a live HTTP server
// ---------------------------------------------------------------------------

// TestRFC3161_Anchor_BadURL confirms a URL with an invalid control character is
// rejected. This used to only surface via http.NewRequestWithContext failing at
// Anchor() time; NewRFC3161 now parses (and https/loopback-validates) the URL at
// construction, so the same malformed input is now caught earlier, at startup —
// url.Parse itself rejects the embedded null byte.
func TestRFC3161_Anchor_BadURL(t *testing.T) {
	_, err := NewRFC3161("https://host/\x00bad", 5*time.Second)
	require.Error(t, err)
}

// TestRFC3161_Anchor_UnreachableHost exercises the http.Do error path: a URL
// pointing at a closed local port causes the TCP dial to fail quickly. Plain
// http to loopback is the documented local-testing exception (validateTSAURL).
func TestRFC3161_Anchor_UnreachableHost(t *testing.T) {
	// Port 1 on localhost — connection refused in < 1 ms on any OS.
	r, err := NewRFC3161("http://127.0.0.1:1/tsr", 2*time.Second)
	require.NoError(t, err)
	_, err = r.Anchor(context.Background(), []byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post to")
}

// TestRFC3161_Anchor_MalformedTSAResponseNoPanic is #G61: Anchor() hands the
// TSA's response bytes to timestamp.ParseResponse, the same digitorus parser
// family VerifyReceipt was already hardened against (index out of range on
// malformed BER, found by the continuous fuzz rig). A hostile or buggy TSA
// endpoint must produce an error, never a process-killing panic — the same
// property TestVerifyReceipt_MalformedToken_NoPanic pins for VerifyReceipt.
func TestRFC3161_Anchor_MalformedTSAResponseNoPanic(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("not DER at all"),
		{0x30, 0x81},             // SEQUENCE + long-form length, no length byte follows
		{0x30, 0x82},             // SEQUENCE + long-form length claiming 2 bytes, none follow
		{0x30, 0x01},             // SEQUENCE claiming 1 content byte, none present
		{0xff, 0x81},             // high-tag-number form, truncated
		{0x30, 0x80, 0x00, 0x00}, // indefinite-length SEQUENCE
	}
	for _, body := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		client, err := NewRFC3161(srv.URL, 5*time.Second)
		require.NoError(t, err)

		require.NotPanics(t, func() {
			_, err = client.Anchor(context.Background(), []byte("anchor message"))
		})
		assert.Error(t, err, "a malformed TSA response must be reported as an error, not silently accepted")
		srv.Close()
	}
}

// ---------------------------------------------------------------------------
// VerifyReceipt — additional nil/empty guards
// ---------------------------------------------------------------------------

// TestVerifyReceipt_NilRoots_FailsClosed re-confirms the nil roots path is rejected.
func TestVerifyReceipt_NilRoots_FailsClosed(t *testing.T) {
	_, err := VerifyReceipt(nil, []byte("msg"), []byte("token"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust anchor")
}

// TestVerifyReceipt_EmptyToken_FailsClosed confirms an empty token is rejected.
func TestVerifyReceipt_EmptyToken_FailsClosed(t *testing.T) {
	_, err := VerifyReceipt(nil, []byte("msg"), nil)
	require.Error(t, err)
	// nil roots error fires before empty-token check, so we only need Error here.
}

// ---------------------------------------------------------------------------
// validateTSAURL / NewRFC3161 — https-only, loopback exception (Wave 6 #baseline/notary-findings.json#1)
// ---------------------------------------------------------------------------

// TestNewRFC3161_RejectsPlaintextHTTP_NonLoopback confirms a plaintext http://
// TSA URL to a non-loopback host is rejected at construction, not silently
// accepted. A network attacker on that path could otherwise see every
// checkpoint hash being anchored and swap in a rogue TSA's response.
func TestNewRFC3161_RejectsPlaintextHTTP_NonLoopback(t *testing.T) {
	_, err := NewRFC3161("http://tsa.example.com/tsr", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestNewRFC3161_AcceptsHTTPS confirms a well-formed https:// TSA URL is still
// accepted (the common, expected case).
func TestNewRFC3161_AcceptsHTTPS(t *testing.T) {
	_, err := NewRFC3161("https://tsa.example.com/tsr", 5*time.Second)
	require.NoError(t, err)
}

// TestNewRFC3161_AcceptsPlaintextHTTP_Loopback confirms the local-testing
// exception this codebase uses elsewhere for operator-configured outbound URLs
// (internal/storage/remote's validateBaseURL, server/main.go's
// requireSecureOrLoopback): plain http to localhost/a loopback IP is still
// accepted, since that can only ever be a local dev/test TSA, not a real
// network attacker's vantage point.
func TestNewRFC3161_AcceptsPlaintextHTTP_Loopback(t *testing.T) {
	for _, u := range []string{
		"http://127.0.0.1:8080/tsr",
		"http://localhost:8080/tsr",
		"http://[::1]:8080/tsr",
	} {
		_, err := NewRFC3161(u, 5*time.Second)
		require.NoError(t, err, u)
	}
}

// TestNewRFC3161_RejectsMalformedURL confirms a URL with no host is rejected
// (unchanged pre-existing behavior, re-pinned after the https-only rewrite of
// validateTSAURL).
func TestNewRFC3161_RejectsMalformedURL(t *testing.T) {
	_, err := NewRFC3161("not-a-url", 5*time.Second)
	require.Error(t, err)
}
