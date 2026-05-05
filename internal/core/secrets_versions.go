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
