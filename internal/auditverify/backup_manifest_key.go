package auditverify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// backupManifestKeyInfo/backupManifestKeyIDInfo domain-separate the
// backup-manifest-signing key (and its public fingerprint) from every other
// use of the KEK -- most importantly from the audit-checkpoint key
// (internal/encryption's auditCheckpointKeyInfo), per design-b3-backup-v2.md
// §5.2's explicit decision: the manifest key is its own, independently
// derived key, never the audit-checkpoint key reused for a second protocol.
// Bump the suffix only if the derivation scheme changes.
const (
	backupManifestKeyInfo   = "keyorix-backup-manifest-signing-key-v1"
	backupManifestKeyIDInfo = "keyorix-backup-manifest-signing-key-id-v1"
)

// MinKEKLen is the shortest KEK, in bytes, that the KEK-derived HKDF keys
// accept: 112 bits, the minimum HKDF input-key length the Go FIPS 140-3 module
// allows. Under GODEBUG=fips140=only crypto/hkdf panics on anything shorter, so
// every KEK-derivation helper (this package's DeriveBackupManifestKey and
// internal/encryption's evidence-signing and audit-checkpoint derivations)
// checks it up front and returns a *KEKTooShortError instead, in every FIPS
// mode alike. Real KEKs are 32 bytes (crypto.KEKSize); this is a floor against
// a misbehaving provider or caller, not a supported size.
const MinKEKLen = 14

// ErrKEKTooShort is the sentinel every *KEKTooShortError matches with errors.Is.
var ErrKEKTooShort = errors.New("KEK shorter than the 112-bit minimum")

// KEKTooShortError reports a KEK below MinKEKLen handed to a KEK-derivation
// helper. No key is derived: the caller must fail closed (no signing or
// checkpoint key at all, never a zero or placeholder key).
type KEKTooShortError struct {
	Purpose string // which key was being derived, e.g. "backup-manifest key"
	Len     int    // the KEK length that was rejected
}

func (e *KEKTooShortError) Error() string {
	return fmt.Sprintf("derive %s: KEK is %d bytes, shorter than the %d-byte (112-bit) minimum; refusing to derive a key", e.Purpose, e.Len, MinKEKLen)
}

// Unwrap lets errors.Is(err, ErrKEKTooShort) match.
func (e *KEKTooShortError) Unwrap() error { return ErrKEKTooShort }

// CheckKEKLen returns a *KEKTooShortError when kek is shorter than MinKEKLen.
func CheckKEKLen(purpose string, kek []byte) error {
	if len(kek) < MinKEKLen {
		return &KEKTooShortError{Purpose: purpose, Len: len(kek)}
	}
	return nil
}

// DeriveBackupManifestKey derives the 32-byte backup-manifest-signing HMAC
// key and its 16-byte public key-ID fingerprint from kek via HKDF-SHA256 --
// the identical construction internal/encryption's deriveAuditCheckpointKey
// and deriveEvidenceSignKey already use for their own independently
// domain-separated keys (design §5.2: "identical shape to
// deriveAuditCheckpointKey"), reimplemented here rather than imported: this
// package's own dependency guard (dependency_guard_test.go) forbids
// importing internal/encryption for the same reason it forbids
// internal/core and internal/storage -- this package must independently
// re-derive everything it verifies, not reuse the code that wrote what it's
// checking. Both outputs are pure, deterministic functions of the KEK
// alone, so they are stable across a DEK rotation (same KEK) and only
// change when the KEK itself does. A KEK shorter than MinKEKLen is refused
// with a *KEKTooShortError before any derivation.
func DeriveBackupManifestKey(kek []byte) (key []byte, keyID string, err error) {
	if err := CheckKEKLen("backup-manifest key", kek); err != nil {
		return nil, "", err
	}
	keyR := hkdf.New(sha256.New, kek, nil, []byte(backupManifestKeyInfo))
	key = make([]byte, 32)
	if _, err = io.ReadFull(keyR, key); err != nil {
		return nil, "", fmt.Errorf("derive backup-manifest key: %w", err)
	}
	idR := hkdf.New(sha256.New, kek, nil, []byte(backupManifestKeyIDInfo))
	idBytes := make([]byte, 16)
	if _, err = io.ReadFull(idR, idBytes); err != nil {
		return nil, "", fmt.Errorf("derive backup-manifest key id: %w", err)
	}
	return key, "bmk-" + hex.EncodeToString(idBytes), nil
}
