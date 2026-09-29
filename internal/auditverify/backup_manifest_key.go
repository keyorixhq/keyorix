package auditverify

import (
	"crypto/sha256"
	"encoding/hex"
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
// change when the KEK itself does.
func DeriveBackupManifestKey(kek []byte) (key []byte, keyID string, err error) {
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
