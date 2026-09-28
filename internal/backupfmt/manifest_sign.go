package backupfmt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// canonicalManifestBytes returns m's JSON encoding with Signature cleared --
// exactly the bytes design §5.4 says the signature covers: "the whole
// manifest except the Signature field itself." encoding/json always emits a
// given struct type's fields in declaration order, so this is a
// deterministic canonical encoding without a hand-rolled canonical encoder
// (unlike internal/core's checkpointCanonical, whose null-separated string
// predates this struct existing at all).
func canonicalManifestBytes(m Manifest) ([]byte, error) {
	m.Signature = ""
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("canonicalize manifest: %w", err)
	}
	return b, nil
}

// SignManifest computes m.Signature: HMAC-SHA256 over m's canonical bytes
// (every field except Signature itself) under key -- design §5.2, §5.4.
// key must be auditverify.DeriveBackupManifestKey's output, never the raw
// KEK (decision 1: the KEK itself is never used directly for anything
// beyond deriving other keys, and never persisted unwrapped anywhere).
func SignManifest(m *Manifest, key []byte) error {
	canon, err := canonicalManifestBytes(*m)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canon)
	m.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// VerifyManifestSignature reports whether m.Signature is the valid HMAC
// over m's canonical bytes under key, via constant-time comparison
// (hmac.Equal) -- matching this codebase's standing convention for every
// other secret/signature comparison. Returns false (never panics or errors)
// for a manifest with no Signature at all, which is exactly "invalid" for
// this check's purpose.
func VerifyManifestSignature(m Manifest, key []byte) bool {
	if m.Signature == "" {
		return false
	}
	want := m.Signature
	canon, err := canonicalManifestBytes(m)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canon)
	got := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(got), []byte(want))
}
