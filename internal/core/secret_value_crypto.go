// secret_value_crypto.go — application-layer encryption of secret VALUES at rest.
//
// Secret values are encrypted at the core layer, on the value bytes, BEFORE they are
// handed to the storage backend (c.storage.CreateSecretVersion). This is what makes
// storage.encryption.enabled actually protect secret values, and it works uniformly
// across every backend (local SQLite, Postgres, and remote/ADR-049) precisely because
// it operates on bytes rather than reaching into a *gorm.DB — unlike the former,
// never-wired encryption.SecretEncryption path it replaces.
//
// The scheme is envelope AES-256-GCM (ADR-004) with additional authenticated data
// bound to the secret's identity (SecretAAD: secretID:projectID:versionNumber, #94)
// so a ciphertext blob cannot be transplanted onto a different secret/version and
// still decrypt.
//
// Fail-closed is the governing rule for a security product: an encryption failure on
// write is surfaced, never silently downgraded to a plaintext write; and a row whose
// own metadata marks it encrypted is never returned as if it were plaintext when no
// key is available to decrypt it.
package core

import (
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// encryptVersionValue produces the at-rest representation of a secret value for a new
// version: (storedValue, metadata).
//
//   - With a secret-value encryptor wired (production, storage.encryption.enabled):
//     returns the AAD-bound ciphertext and its serialized metadata. An encryption
//     error is returned as-is — the value is NEVER written in plaintext in this mode.
//   - With no encryptor wired (encryption disabled — dev/test, which prints the loud
//     "ENCRYPTION IS DISABLED" banner at startup): returns the raw value and nil
//     metadata (the caller records empty "{}" metadata, marking a plaintext row).
func (c *KeyorixCore) encryptVersionValue(secret *models.SecretNode, value []byte, versionNumber int) (storedValue []byte, metadata []byte, err error) {
	if c.secretValueEncryptor == nil {
		return value, nil, nil
	}
	aad := encryption.SecretAAD(secret.ID, secret.ProjectID, versionNumber)
	ciphertext, meta, err := c.secretValueEncryptor.EncryptSecretWithAAD(value, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret value: %w", err)
	}
	return ciphertext, meta, nil
}

// decryptVersionValue returns the plaintext value of a stored version, fail-closed.
//
// The row's OWN EncryptionMetadata decides the path, not the presence of a key:
//   - Encrypted row (metadata carries an algorithm): it MUST be decrypted with a wired
//     encryptor. If none is available, this errors rather than handing back ciphertext
//     as though it were plaintext.
//   - Plaintext row (empty "{}" metadata — written while encryption was disabled):
//     returned as-is.
//
// The AAD is reconstructed from the row's identity exactly as encryptVersionValue
// bound it, so a transplanted ciphertext fails authentication.
func (c *KeyorixCore) decryptVersionValue(secret *models.SecretNode, version *models.SecretVersion) ([]byte, error) {
	if !versionIsEncrypted(version.EncryptionMetadata) {
		return version.EncryptedValue, nil
	}
	if c.secretValueEncryptor == nil {
		return nil, fmt.Errorf("secret version %d is encrypted at rest but no encryption key is available to decrypt it — refusing to return raw ciphertext (check storage.encryption / KEYORIX_MASTER_PASSWORD)", version.ID)
	}
	aad := encryption.SecretAAD(secret.ID, secret.ProjectID, version.VersionNumber)
	plaintext, err := c.secretValueEncryptor.DecryptSecretWithAAD(version.EncryptedValue, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret value: %w", err)
	}
	return plaintext, nil
}

// versionIsEncrypted reports whether a stored version's EncryptionMetadata marks it as
// encrypted at rest. Encrypted rows carry a non-empty AES-256-GCM envelope metadata
// (Algorithm set); plaintext rows carry empty "{}" metadata. Malformed/empty metadata
// is treated as plaintext — the fail-closed direction, since a genuinely encrypted
// blob will then fail to parse as plaintext downstream rather than leak.
func versionIsEncrypted(meta models.JSON) bool {
	if len(meta) == 0 {
		return false
	}
	var m struct {
		Algorithm string `json:"algorithm"`
	}
	if err := json.Unmarshal(meta, &m); err != nil {
		return false
	}
	return m.Algorithm != ""
}
