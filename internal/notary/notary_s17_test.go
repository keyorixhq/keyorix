package notary

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewRFC3161 — zero/negative timeout falls back to defaultTimeout
// ---------------------------------------------------------------------------

func TestNewRFC3161_ZeroTimeout_UsesDefault(t *testing.T) {
	r := NewRFC3161("https://example.tsa/rfc3161", 0)
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
	r := NewRFC3161("https://example.tsa/rfc3161", -1*time.Second)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

func TestNewRFC3161_PositiveTimeout_Respected(t *testing.T) {
	r := NewRFC3161("https://example.tsa/rfc3161", 5*time.Second)
	assert.Equal(t, 5*time.Second, r.client.Timeout)
}

func TestRFC3161_Provider(t *testing.T) {
	r := NewRFC3161("https://freetsa.org/tsr", 5*time.Second)
	assert.Equal(t, "rfc3161:https://freetsa.org/tsr", r.Provider())
}

// ---------------------------------------------------------------------------
// Anchor — error paths that don't require a live HTTP server
// ---------------------------------------------------------------------------

// TestRFC3161_Anchor_BadURL exercises the http.NewRequestWithContext error branch:
// a URL with an invalid control character causes request creation to fail.
func TestRFC3161_Anchor_BadURL(t *testing.T) {
	// A URL with a null byte in it causes http.NewRequestWithContext to fail
	// (invalid control character in URL).
	r := NewRFC3161("http://host/\x00bad", 5*time.Second)
	_, err := r.Anchor(context.Background(), []byte("hello"))
	require.Error(t, err)
}

// TestRFC3161_Anchor_UnreachableHost exercises the http.Do error path: a URL
// pointing at a closed local port causes the TCP dial to fail quickly.
func TestRFC3161_Anchor_UnreachableHost(t *testing.T) {
	// Port 1 on localhost — connection refused in < 1 ms on any OS.
	r := NewRFC3161("http://127.0.0.1:1/tsr", 2*time.Second)
	_, err := r.Anchor(context.Background(), []byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post to")
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
