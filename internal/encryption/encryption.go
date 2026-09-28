// encryption.go keeps internal/encryption's public API stable after the pure
// AES-256-GCM AEAD core moved to the leaf package internal/encryption/aead
// (see that package's doc.go for why: fuzz throughput). Types are aliases, so
// values are interchangeable; functions are thin wrappers.
package encryption

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption/aead"
)

// aesCipherSuite is aead.AESCipherSuite — this package's own tests build
// EncryptionMetadata fixtures with it directly.
const aesCipherSuite = aead.AESCipherSuite

// EncryptionMetadata is aead.EncryptionMetadata.
type EncryptionMetadata = aead.EncryptionMetadata

// EncryptedData is aead.EncryptedData.
type EncryptedData = aead.EncryptedData

// EncryptionService is aead.EncryptionService.
type EncryptionService = aead.EncryptionService

// NewEncryptionService creates a new encryption service with the given DEK.
func NewEncryptionService(kek []byte) (*EncryptionService, error) {
	return aead.NewEncryptionService(kek)
}

// GenerateRandomKey generates a cryptographically secure random key
func GenerateRandomKey(size int) ([]byte, error) { return aead.GenerateRandomKey(size) }

// SerializeEncryptedData converts EncryptedData to JSON bytes
func SerializeEncryptedData(data *EncryptedData) ([]byte, error) {
	return aead.SerializeEncryptedData(data)
}

// DeserializeEncryptedData converts JSON bytes to EncryptedData
func DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	return aead.DeserializeEncryptedData(data)
}

// rotateKey re-encrypts data with a new key version, via es's exported
// Decrypt/Encrypt (both now in package aead, reached through the
// EncryptionService alias). A package-level function rather than a method —
// aead.EncryptionService's methods must be exported to cross the package
// boundary via a type alias, and rotateKey is deliberately NOT exported
// (CRYPTO-003: callers outside this package must use the AAD-aware sweep
// path in sweep.go, not this no-AAD rotation).
// WARNING: uses no-AAD decrypt/encrypt and is incompatible with AAD-bound
// ciphertexts (e.g. secret versions encrypted with EncryptWithAAD). To re-key
// AAD-bound ciphertexts, use sweepSecretVersions in sweep.go instead.
func rotateKey(es *EncryptionService, encryptedData *EncryptedData, newKeyVersion string) (*EncryptedData, error) {
	plaintext, err := es.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt for key rotation: %w", err)
	}
	return es.Encrypt(plaintext, newKeyVersion)
}

// DefaultKEKIterations is the PBKDF2-HMAC-SHA256 iteration count GenerateKEK falls
// back to when the caller passes 0. It is DEFINED AS crypto.PBKDF2Iterations — the single
// source of truth for the KEK-derivation work factor — so the value GenerateKEK /
// RotateKEKPassphrase derive with can never drift from the value the passphrase provider
// used to wrap the on-disk DEK (a drift would make rotate-kek derive a non-matching KEK: a
// fail-closed break). Do not replace this with a bare literal; that reintroduces the
// two-independent-constants hazard F-ENC-1 closed (2026-09-14 review). 600,000 matches
// OWASP's current PBKDF2-HMAC-SHA256 minimum; the prior fallback (100,000) was ~6x weaker.
const DefaultKEKIterations = crypto.PBKDF2Iterations

// GenerateKEK generates a new Key Encryption Key using PBKDF2. iterations == 0 uses
// DefaultKEKIterations.
func GenerateKEK(password string, salt []byte, iterations int) []byte {
	if iterations == 0 {
		iterations = DefaultKEKIterations
	}
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

// SecretAAD returns the canonical Additional Authenticated Data for a secret version.
// Format: "keyorix:v2:<secretID>:<projectID>:<versionNumber>"
// This binds the ciphertext to a specific secret + project + version, preventing
// ciphertext transplant attacks (copying an encrypted value between rows). The
// implementation moved to ports.SecretAAD (ADR-109 step 5, small, pure,
// stdlib-only) so internal/core can build it without importing
// internal/encryption; this stays a two-line re-export so existing callers
// (server/http and this package's own tests, which call it by name) keep
// working unchanged.
func SecretAAD(secretID, projectID uint, versionNumber int) []byte {
	return ports.SecretAAD(secretID, projectID, versionNumber)
}

// MFASecretAAD returns the AAD for a user's encrypted TOTP shared secret (#94),
// binding the ciphertext to the owning user so a DB-write attacker cannot transplant
// one user's encrypted TOTP seed onto another user's row. MFASecret is keyed 1:1 on
// UserID (a uniqueIndex, never reassigned), so this alone is a stable, sufficient
// owning identity. Domain-separated from SecretAAD's "keyorix:v2:" prefix so a
// transplant across CATEGORIES (e.g. a SecretVersion blob pasted into an MFASecret
// row) also fails, not just a transplant within the same category. The
// implementation moved to ports.MFASecretAAD (ADR-109 step 5) alongside SecretAAD
// above — see its doc comment for the same two-line-re-export rationale.
func MFASecretAAD(userID uint) []byte {
	return ports.MFASecretAAD(userID)
}

// APITokenAAD returns the AAD for a user's encrypted personal-access token
// (AUTH-CRYPTO-002), binding the ciphertext to the issuing user.
func APITokenAAD(userID uint) []byte {
	return []byte(fmt.Sprintf("keyorix:apitoken:v1:%d", userID))
}

// PasswordResetTokenAAD returns the AAD for a user's encrypted password-reset token
// (AUTH-CRYPTO-001), binding the ciphertext to the owning user.
func PasswordResetTokenAAD(userID uint) []byte {
	return []byte(fmt.Sprintf("keyorix:pwreset:v1:%d", userID))
}

// DynamicSecretConfigAAD returns the AAD for a dynamic-secret config's encrypted admin
// DSN (#94), binding the ciphertext to the config's identity and project/environment
// scope. None of configID/projectID/environmentID are reassigned after creation (see
// DynamicSecretConfig — only Classification is ever updated). The implementation moved
// to ports.DynamicSecretConfigAAD (ADR-109 step 5) — see SecretAAD's doc comment above
// for the same two-line-re-export rationale.
func DynamicSecretConfigAAD(configID, projectID, environmentID uint) []byte {
	return ports.DynamicSecretConfigAAD(configID, projectID, environmentID)
}

// DynamicSecretLeaseAAD returns the AAD for an issued dynamic-secret lease's encrypted
// credential (#94), binding the ciphertext to the lease's identity and owning config —
// leases are issue-once (revoke/expire only), never reassigned to a different config.
// Takes the lease's external string LeaseID (a random token, gorm:"uniqueIndex"), not
// its numeric primary key — LeaseID is generated before the row is inserted, so the
// caller can bind and encrypt the credential in one pass rather than needing a
// two-phase insert-then-update to learn an auto-increment ID first. The implementation
// moved to ports.DynamicSecretLeaseAAD (ADR-109 step 5) — see SecretAAD's doc comment
// above for the same two-line-re-export rationale.
func DynamicSecretLeaseAAD(leaseID string, configID uint) []byte {
	return ports.DynamicSecretLeaseAAD(leaseID, configID)
}
