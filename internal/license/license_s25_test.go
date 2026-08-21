package license

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// TestParsePrivateKeyPEM_Valid confirms a PKCS#8-encoded ed25519 private key round-trips.
func TestParsePrivateKeyPEM_Valid(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := ParsePrivateKeyPEM(pemBlock)
	require.NoError(t, err)
	assert.Equal(t, priv, got, "round-tripped key must match original")
}

// TestParsePrivateKeyPEM_InvalidDER checks that a PEM block with corrupt DER content
// returns an error from ParsePrivateKeyPEM.
func TestParsePrivateKeyPEM_InvalidDER(t *testing.T) {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not valid der")})
	_, err := ParsePrivateKeyPEM(pemBlock)
	assert.Error(t, err, "corrupt DER must return an error")
	assert.Contains(t, err.Error(), "parse signing key")
}

// TestParsePrivateKeyPEM_NotEd25519 checks that a valid PKCS#8 key of the wrong type
// (ECDSA, not ed25519) is rejected with the appropriate error.
func TestParsePrivateKeyPEM_NotEd25519(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = ParsePrivateKeyPEM(pemBlock)
	assert.Error(t, err, "non-ed25519 key must be rejected")
	assert.Contains(t, err.Error(), "not ed25519")
}

// TestParseToken_BadSigBase64 targets the "decode signature" error branch in parseToken.
// We craft a token whose payload is valid base64 JSON but whose signature part is not
// valid base64url.
func TestParseToken_BadSigBase64(t *testing.T) {
	// Encode a minimal valid payload, but give an invalid base64 for the sig.
	lic := License{
		Licensee: "ACME", Plan: "enterprise",
		KeyID:    "k",
		NotAfter: time.Now().Add(time.Hour),
	}
	payload, err := json.Marshal(&lic)
	require.NoError(t, err)

	validPayload := base64.RawURLEncoding.EncodeToString(payload)
	badSig := "!!!invalid-base64!!!"
	token := validPayload + "." + badSig

	st := Evaluate(token, trust.NewRegistry(), "", time.Now(), time.Hour)
	assert.Equal(t, StateInvalid, st.State, "bad-sig base64 must degrade to invalid")
	assert.False(t, st.Grants(), "degraded state must not grant features")
}

// TestParseToken_BadPayloadJSON covers the "parse payload" branch where the payload
// decodes successfully from base64 but is not valid JSON.
func TestParseToken_BadPayloadJSON(t *testing.T) {
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	token := notJSON + "." + sig

	st := Evaluate(token, trust.NewRegistry(), "", time.Now(), time.Hour)
	assert.Equal(t, StateInvalid, st.State)
	assert.False(t, st.Grants())
}

// TestEvaluate_EmptyKeyID verifies that a token with an empty key_id field degrades
// to StateInvalid (the "license has no key-id" check after parseToken succeeds).
func TestEvaluate_EmptyKeyID(t *testing.T) {
	// Build a token manually whose key_id is blank, bypassing Issue's own validation.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	lic := License{
		Licensee: "ACME",
		NotAfter: time.Now().Add(time.Hour),
		KeyID:    "", // deliberately empty — Issue would reject this, so bypass it
	}
	payload, err := json.Marshal(&lic)
	require.NoError(t, err)

	sig := ed25519.Sign(priv, payload)
	token := enc(payload) + "." + enc(sig)

	st := Evaluate(token, trust.NewRegistry(), "", time.Now(), time.Hour)
	assert.Equal(t, StateInvalid, st.State, "empty key-id must degrade to invalid")
	assert.Contains(t, st.Reason, "no key-id")
	assert.False(t, st.Grants())
}

// TestIssue_MarshalError covers the json.Marshal error branch in Issue. time.Time's
// MarshalJSON rejects years outside [0,9999], so a NotAfter far in the future makes
// json.Marshal(&lic) fail even though all of Issue's own field validations pass.
func TestIssue_MarshalError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	lic := License{
		Licensee: "ACME",
		KeyID:    "k",
		NotAfter: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), // year out of range for MarshalJSON
	}
	token, err := Issue(lic, priv)
	assert.Error(t, err, "an unmarshalable NotAfter must surface the json.Marshal error")
	assert.Empty(t, token, "no token should be produced on marshal failure")
}

// TestStatus_HasFeature_DegradedStates checks HasFeature returns false for every
// non-granting state, covering the short-circuit in HasFeature.
func TestStatus_HasFeature_DegradedStates(t *testing.T) {
	feat := "airgap_updates"
	for _, state := range []State{StateExpired, StateInvalid, StateNone} {
		st := Status{State: state, Features: []string{feat}}
		assert.False(t, st.HasFeature(feat), "state %s must not grant features", state)
	}
}

// TestGate_WhitespaceToken verifies that a token consisting of only whitespace
// is treated as empty (StateNone) and not as a malformed token (StateInvalid).
func TestGate_WhitespaceToken(t *testing.T) {
	g := NewGate("   \t\n  ", trust.NewRegistry(), "", 0)
	st := g.Status()
	assert.Equal(t, StateNone, st.State)
	assert.False(t, st.Grants())
}
