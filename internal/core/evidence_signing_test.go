package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceSignature_RoundTrip(t *testing.T) {
	c := &KeyorixCore{}
	c.SetEvidenceSignKey([]byte("0123456789abcdef0123456789abcdef"), "v1")
	data := []byte(`{"generated_at":"2026-06-15T00:00:00Z"}`)

	sig, ok := c.signEvidence(data)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(sig, "v1:"))

	res := c.VerifyEvidenceSignature(data, sig)
	assert.True(t, res.Valid)

	// Tampered data → invalid (not authentic).
	res = c.VerifyEvidenceSignature([]byte(`{"generated_at":"changed"}`), sig)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "does not match")

	// Signature from a superseded key version → reported distinctly, not a mismatch.
	superseded := "v0:" + strings.SplitN(sig, ":", 2)[1]
	res = c.VerifyEvidenceSignature(data, superseded)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "superseded")
	assert.Equal(t, "v0", res.KeyVersion)
	assert.Equal(t, "v1", res.CurrentVersion)

	// Malformed signature.
	assert.False(t, c.VerifyEvidenceSignature(data, "garbage").Valid)
}

// TestEvidenceSignature_WrongKeySameVersionRejected pins that the key-version label is NOT a
// credential: a signature carrying the right version prefix but produced by a DIFFERENT key
// (another deployment) must be rejected as a mismatch, not accepted. The HMAC's secret key is
// what proves authenticity; the version label is public. A regression that only compared the
// version string (skipping the constant-time HMAC check) would pass every other test but make
// evidence signatures trivially forgeable — this catches it.
func TestEvidenceSignature_WrongKeySameVersionRejected(t *testing.T) {
	data := []byte(`{"generated_at":"2026-06-15T00:00:00Z"}`)

	// A different deployment signs the same data with ITS OWN key, under the same "v1" label.
	other := &KeyorixCore{}
	other.SetEvidenceSignKey([]byte("ffffffffffffffffffffffffffffffff"), "v1")
	foreignSig, ok := other.signEvidence(data)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(foreignSig, "v1:"))

	// This deployment has a DIFFERENT key under the same version label. The version matches
	// (so we reach the HMAC check, not the superseded-version early-return), but the key
	// differs, so verification must report a mismatch.
	c := &KeyorixCore{}
	c.SetEvidenceSignKey([]byte("0123456789abcdef0123456789abcdef"), "v1")
	res := c.VerifyEvidenceSignature(data, foreignSig)
	assert.False(t, res.Valid, "a signature from a different deployment's key must not verify")
	assert.Contains(t, res.Reason, "does not match")
	assert.NotContains(t, res.Reason, "superseded", "the version matched — the HMAC check, not version handling, must reject it")
}

func TestEvidenceSignature_UnavailableWithoutKey(t *testing.T) {
	c := &KeyorixCore{}
	assert.False(t, c.EvidenceSigningAvailable())
	_, ok := c.signEvidence([]byte("x"))
	assert.False(t, ok)
	res := c.VerifyEvidenceSignature([]byte("x"), "v1:ab")
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "unavailable")
}
