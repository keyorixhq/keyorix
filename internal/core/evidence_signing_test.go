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

func TestEvidenceSignature_UnavailableWithoutKey(t *testing.T) {
	c := &KeyorixCore{}
	assert.False(t, c.EvidenceSigningAvailable())
	_, ok := c.signEvidence([]byte("x"))
	assert.False(t, ok)
	res := c.VerifyEvidenceSignature([]byte("x"), "v1:ab")
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "unavailable")
}
