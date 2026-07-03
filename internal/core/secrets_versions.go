// secrets_versions.go — storeSecretVersion: shared helper used by Create, Update, and Rotate.
//
// Full version query/retrieval functions live in versions.go.
// For CRUD operations see secrets.go. For validation see secrets_validation.go.
package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// storeSecretVersion writes a new version row for the given secret.
// Routes through the encryption service if wired; otherwise stores raw bytes.
// Used by CreateSecret, UpdateSecret, and RotateSecret.
func (c *KeyorixCore) storeSecretVersion(ctx context.Context, secret *models.SecretNode, value []byte, versionNumber int) error {
	if c.encryption != nil {
		_, err := c.encryption.StoreSecret(secret, value)
		return err
	}
	version := &models.SecretVersion{
		SecretNodeID:       secret.ID,
		VersionNumber:      versionNumber,
		EncryptedValue:     value,
		EncryptionMetadata: []byte("{}"),
		ReadCount:          0,
		CreatedAt:          time.Now(),
	}
	_, err := c.storage.CreateSecretVersion(ctx, version)
	return err
}

// maxRotateVersionAttempts bounds storeNextSecretVersion's retry loop — a safety valve,
// not an expected outcome. Even under the empirically-reproduced #121 contention (15
// concurrent rotations of one secret), a handful of retries always suffices; if this bound
// is ever hit it indicates something is wrong beyond ordinary concurrent rotation traffic.
const maxRotateVersionAttempts = 20

// isVersionConflict reports whether err is the sentinel storage.ErrDuplicateSecretVersion
// (the non-encrypted storeSecretVersion path, which wraps it explicitly) or looks like a
// raw unique-constraint violation from either backing DB driver (the encrypted path's
// SecretEncryption.StoreSecret writes its version row directly inside its own
// transaction, bypassing the storage-layer wrapper that attaches the sentinel — so the
// underlying driver error text is matched directly here too, mirroring
// store.isUniqueViolation).
func isVersionConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, storage.ErrDuplicateSecretVersion) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || // SQLite
		strings.Contains(msg, "duplicate key value violates unique constraint") // Postgres
}

// storeNextSecretVersion resolves the next version number for secret and stores value
// under it, retrying on a lost race rather than failing the rotation outright (#121).
// GetLatestSecretVersion -> +1 -> storeSecretVersion is inherently a read-then-write
// sequence; the uniq_secret_versions_node_version DB index (storage.
// ensureSecretVersionIndex) is what actually makes concurrent rotations of the same
// secret safe — this retry loop is what lets a rotation that lost the race succeed anyway
// instead of surfacing a spurious "rotation failed" to an ordinary concurrent caller (an
// operational timing coincidence, not a conflict either caller did anything wrong to
// cause). Used by RotateSecret; CreateSecret/UpdateSecret call storeSecretVersion
// directly since they aren't racing an unbounded number of other version writers for the
// same secret_id the way concurrent rotations are.
func (c *KeyorixCore) storeNextSecretVersion(ctx context.Context, secret *models.SecretNode, value []byte) error {
	var lastErr error
	for attempt := 0; attempt < maxRotateVersionAttempts; attempt++ {
		latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
		nextVersionNumber := 1
		if err == nil && latestVersion != nil {
			nextVersionNumber = latestVersion.VersionNumber + 1
		}
		lastErr = c.storeSecretVersion(ctx, secret, value, nextVersionNumber)
		if lastErr == nil {
			return nil
		}
		if !isVersionConflict(lastErr) {
			return lastErr
		}
		// Lost the race to another concurrent rotation of the same secret — re-read the
		// now-current latest version and retry.
	}
	return fmt.Errorf("exceeded %d attempts resolving the next secret version number: %w", maxRotateVersionAttempts, lastErr)
}
