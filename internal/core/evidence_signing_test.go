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
	const fname = "keyorix-evidence-20260615T000000Z.json"

	sig, ok := c.signEvidence(fname, data)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(sig, "v1:"))

	res := c.VerifyEvidenceSignature(fname, data, sig)
	assert.True(t, res.Valid)

	// Tampered data → invalid (not authentic).
	res = c.VerifyEvidenceSignature(fname, []byte(`{"generated_at":"changed"}`), sig)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "does not match")

	// Wrong filename → invalid (AUD-009: signature is filename-bound).
	res = c.VerifyEvidenceSignature("keyorix-evidence-20260101T000000Z.json", data, sig)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "does not match")

	// Signature from a superseded key version → reported distinctly, not a mismatch.
	superseded := "v0:" + strings.SplitN(sig, ":", 2)[1]
	res = c.VerifyEvidenceSignature(fname, data, superseded)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "superseded")
	assert.Equal(t, "v0", res.KeyVersion)
	assert.Equal(t, "v1", res.CurrentVersion)

	// Malformed signature.
	assert.False(t, c.VerifyEvidenceSignature(fname, data, "garbage").Valid)
}

// TestEvidenceSignature_WrongKeySameVersionRejected pins that the key-version label is NOT a
// credential: a signature carrying the right version prefix but produced by a DIFFERENT key
// (another deployment) must be rejected as a mismatch, not accepted. The HMAC's secret key is
// what proves authenticity; the version label is public. A regression that only compared the
// version string (skipping the constant-time HMAC check) would pass every other test but make
// evidence signatures trivially forgeable — this catches it.
func TestEvidenceSignature_WrongKeySameVersionRejected(t *testing.T) {
	data := []byte(`{"generated_at":"2026-06-15T00:00:00Z"}`)
	const fname = "keyorix-evidence-20260615T000000Z.json"

	// A different deployment signs the same data with ITS OWN key, under the same "v1" label.
	other := &KeyorixCore{}
	other.SetEvidenceSignKey([]byte("ffffffffffffffffffffffffffffffff"), "v1")
	foreignSig, ok := other.signEvidence(fname, data)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(foreignSig, "v1:"))

	// This deployment has a DIFFERENT key under the same version label. The version matches
	// (so we reach the HMAC check, not the superseded-version early-return), but the key
	// differs, so verification must report a mismatch.
	c := &KeyorixCore{}
	c.SetEvidenceSignKey([]byte("0123456789abcdef0123456789abcdef"), "v1")
	res := c.VerifyEvidenceSignature(fname, data, foreignSig)
	assert.False(t, res.Valid, "a signature from a different deployment's key must not verify")
	assert.Contains(t, res.Reason, "does not match")
	assert.NotContains(t, res.Reason, "superseded", "the version matched — the HMAC check, not version handling, must reject it")
}

// TestEvidenceSignature_PreFixPackReportedSupersededNotTampered pins the
// non-regression the #268 fix depends on: switching the evidence-signing key's
// derivation source (DEK -> KEK, so a routine DEK rotation stops invalidating
// signatures — see encryption.Service.EvidenceSignKey) also changes the "key
// version" label's format going forward (old scheme: the DEK's own rotation
// version, e.g. "v1700000000"; new scheme: an "esk-<hex>" KEK fingerprint). An old
// pack signed before this fix shipped, under the old scheme's version label, must
// still be reported as made under a SUPERSEDED key version — exactly the existing,
// honest, non-misleading outcome documented at the top of this file — never as
// freshly "tampered" just because the fix changed the label format.
func TestEvidenceSignature_PreFixPackReportedSupersededNotTampered(t *testing.T) {
	data := []byte(`{"generated_at":"2026-01-01T00:00:00Z"}`)
	const fname = "keyorix-evidence-20260101T000000Z.json"

	// Simulate the pack as it would have been signed BEFORE this fix, under the
	// old DEK-rotation-version-derived label.
	oldPackCore := &KeyorixCore{}
	oldPackCore.SetEvidenceSignKey([]byte("0123456789abcdef0123456789abcdef"), "v1700000000")
	sig, ok := oldPackCore.signEvidence(fname, data)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(sig, "v1700000000:"))

	// The running deployment now uses the NEW (KEK-derived) key and its
	// "esk-<hex>"-style version label, wired exactly as SetEvidenceSignKey is
	// called from server/main.go after this fix.
	c := &KeyorixCore{}
	c.SetEvidenceSignKey([]byte("ffffffffffffffffffffffffffffffff"), "esk-0123456789abcdef0123456789abcd")

	res := c.VerifyEvidenceSignature(fname, data, sig)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "superseded")
	assert.NotContains(t, res.Reason, "does not match", "an old-scheme pack must be reported as superseded, not tampered")
	assert.Equal(t, "v1700000000", res.KeyVersion)
	assert.Equal(t, "esk-0123456789abcdef0123456789abcd", res.CurrentVersion)
}

func TestEvidenceSignature_UnavailableWithoutKey(t *testing.T) {
	c := &KeyorixCore{}
	assert.False(t, c.EvidenceSigningAvailable())
	_, ok := c.signEvidence("pack.json", []byte("x"))
	assert.False(t, ok)
	res := c.VerifyEvidenceSignature("pack.json", []byte("x"), "v1:ab")
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "unavailable")
}
