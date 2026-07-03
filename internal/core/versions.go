package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetSecretVersions retrieves all versions of a secret.
func (c *KeyorixCore) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if _, err := c.storage.GetSecret(ctx, secretID); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return versions, nil
}

// GetSecretVersionsWithPermissionCheck retrieves all versions of a secret with permission validation.
func (c *KeyorixCore) GetSecretVersionsWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetSecretVersions(ctx, secretID)
}

// GetSecretVersion retrieves a specific version of a secret.
func (c *KeyorixCore) GetSecretVersion(ctx context.Context, secretID uint, versionNumber int) (*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if versionNumber <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version number must be positive")
	}
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, version := range versions {
		if version.VersionNumber == versionNumber {
			return version, nil
		}
	}
	return nil, fmt.Errorf("%s: version %d not found", i18n.T("ErrorVersionNotFound", nil), versionNumber)
}

// GetSecretVersionWithPermissionCheck retrieves a specific version of a secret with permission validation.
func (c *KeyorixCore) GetSecretVersionWithPermissionCheck(ctx context.Context, secretID, userID uint, versionNumber int) (*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetSecretVersion(ctx, secretID, versionNumber)
}

// GetLatestSecretVersion retrieves the latest version of a secret.
func (c *KeyorixCore) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNoVersionsFound", nil))
	}
	// Versions are ordered by version DESC, so first is latest.
	return versions[0], nil
}

// GetLatestSecretVersionWithPermissionCheck retrieves the latest version of a secret with permission validation.
func (c *KeyorixCore) GetLatestSecretVersionWithPermissionCheck(ctx context.Context, secretID, userID uint) (*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.ValidateSecretAccess(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetLatestSecretVersion(ctx, secretID)
}

// GetSecretValue retrieves the decrypted value of the latest version of a secret.
func (c *KeyorixCore) GetSecretValue(ctx context.Context, secretID uint) ([]byte, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}
	if secret.Status == SecretStatusSuspended {
		return nil, fmt.Errorf("secret is suspended")
	}
	version, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}
	return c.readVersionValue(ctx, secret, version)
}

// GetSecretValueWithPermissionCheck retrieves the decrypted value with permission validation.
func (c *KeyorixCore) GetSecretValueWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]byte, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.ValidateSecretAccess(ctx, secretID, userID); err != nil {
		return nil, err
	}
	// Delegate to base method — avoids duplicating max-reads logic.
	return c.GetSecretValue(ctx, secretID)
}

// GetSecretValueByVersion retrieves the decrypted value of a specific version of a secret.
func (c *KeyorixCore) GetSecretValueByVersion(ctx context.Context, secretID uint, versionNumber int) ([]byte, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if versionNumber <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version number must be positive")
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}
	if secret.Status == SecretStatusSuspended {
		return nil, fmt.Errorf("secret is suspended")
	}
	version, err := c.GetSecretVersion(ctx, secretID, versionNumber)
	if err != nil {
		return nil, err
	}
	// Route through the shared enforcement path so a by-version read is subject to the
	// same atomic max-reads cap as the latest-version read — defense-in-depth against a
	// future caller that uses the by-version path to bypass the read ceiling.
	return c.readVersionValue(ctx, secret, version)
}

// EventSecretRolledBack is audited when a secret is restored to a prior version.
const EventSecretRolledBack = "secret.rolled_back"

// RollbackSecret restores a secret to the value of a prior version by re-instating that
// value as a NEW version — version history stays append-only (the rollback itself is a
// new version, so it too can be undone). The caller (transport) must have enforced
// scoped secrets.write. Unlike a value read, this fetches the historical version
// directly (no max-reads / expiry guard) since a restore is a write, not a use.
func (c *KeyorixCore) RollbackSecret(ctx context.Context, secretID uint, targetVersion int, actorID uint, actorName string) (*models.SecretNode, error) {
	version, err := c.GetSecretVersion(ctx, secretID, targetVersion)
	if err != nil {
		return nil, err
	}
	latest, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err == nil && latest != nil && latest.VersionNumber == targetVersion {
		return nil, fmt.Errorf("version %d is already the current version", targetVersion)
	}
	var val []byte
	if c.encryption != nil {
		val, err = c.encryption.RetrieveSecret(version.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to read version %d: %w", targetVersion, err)
		}
	} else {
		val = version.EncryptedValue
	}
	secret, err := c.RotateSecret(ctx, secretID, val, actorName)
	if err != nil {
		return nil, err
	}
	uid := actorID
	sid := secretID
	c.writeAuditEvent(ctx, EventSecretRolledBack, &uid, &sid,
		fmt.Sprintf("rolled back secret %q to the value of version %d", secret.Name, targetVersion))
	return secret, nil
}

// GetSecretValueByVersionWithPermissionCheck retrieves the decrypted value of a specific version with permission validation.
func (c *KeyorixCore) GetSecretValueByVersionWithPermissionCheck(ctx context.Context, secretID, userID uint, versionNumber int) ([]byte, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.ValidateSecretAccess(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetSecretValueByVersion(ctx, secretID, versionNumber)
}

// readVersionValue applies max-reads enforcement and decryption for a secret version.
// Shared by GetSecretValue and GetSecretValueWithPermissionCheck.
func (c *KeyorixCore) readVersionValue(ctx context.Context, secret *models.SecretNode, version *models.SecretVersion) ([]byte, error) {
	if secret.MaxReads != nil && *secret.MaxReads > 0 {
		// Atomic check-and-increment against the SECRET (not the version, #133): the
		// conditional UPDATE serializes concurrent reads on the row, so they can never
		// collectively exceed the cap, and the count carries forward across rotate/
		// rollback creating a new version — a per-version counter would reset to zero
		// on every new version, letting a burn-after-N-reads secret become re-readable
		// simply by rolling back. Fail closed — if enforcement can't be confirmed,
		// don't hand back the value.
		ok, err := c.storage.TryIncrementSecretNodeReadCount(ctx, secret.ID, *secret.MaxReads)
		if err != nil {
			return nil, fmt.Errorf("max-reads enforcement failed: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("%s", i18n.T("ErrorMaxReadsExceeded", nil))
		}
		// Best-effort per-version read_count (CLI/gRPC display only, not the
		// enforcement mechanism above): a failure here must not block an already-
		// authorized read.
		_, _ = c.storage.TryIncrementSecretReadCount(ctx, version.ID, *secret.MaxReads)
	}
	if c.encryption != nil {
		return c.encryption.RetrieveSecret(version.ID)
	}
	return version.EncryptedValue, nil
}
