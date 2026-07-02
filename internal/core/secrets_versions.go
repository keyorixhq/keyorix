// secrets_versions.go — storeSecretVersion: shared helper used by Create, Update, and Rotate.
//
// Full version query/retrieval functions live in versions.go.
// For CRUD operations see secrets.go. For validation see secrets_validation.go.
package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// storeSecretVersion writes a new version row for the given secret, assigning
// the next version number atomically. Routes through the encryption service if
// wired; otherwise stores raw bytes. Used by CreateSecret, UpdateSecret, and
// RotateSecret — including auto-rotation, which calls RotateSecret directly, so
// a manual rotation racing a scheduled one goes through the same protection.
//
// #121: this used to take a caller-computed versionNumber (fetched via a
// separate GetLatestSecretVersion call moments earlier) — two concurrent
// callers for the SAME secret could both compute the SAME "next" number and
// both insert, producing a duplicate version (GetLatest then returns one
// non-deterministically) or losing whichever write lost the race. The version
// number is now computed and retried atomically inside the storage layer
// (CreateNextSecretVersion / encryption.StoreSecret), so callers no longer
// need — or are able — to pass one in.
func (c *KeyorixCore) storeSecretVersion(ctx context.Context, secret *models.SecretNode, value []byte) error {
	if c.encryption != nil {
		_, err := c.encryption.StoreSecret(secret, value)
		return err
	}
	version := &models.SecretVersion{
		SecretNodeID:       secret.ID,
		EncryptedValue:     value,
		EncryptionMetadata: []byte("{}"),
		ReadCount:          0,
		CreatedAt:          time.Now(),
	}
	_, err := c.storage.CreateNextSecretVersion(ctx, version)
	return err
}
