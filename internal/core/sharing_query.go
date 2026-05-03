// sharing_query.go — ListSharedSecrets, ListSecretShares, ListSharesByUser, CheckSharePermission.
//
// Read-only query operations over share records.
// For share create/update/revoke see sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSharedSecrets lists all secrets shared with a user.
func (c *KeyorixCore) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	secrets, err := c.storage.ListSharedSecrets(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}
	return secrets, nil
}

// ListSecretShares lists all shares for a specific secret.
func (c *KeyorixCore) ListSecretShares(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if _, err := c.GetSecret(ctx, secretID); err != nil {
		return nil, err
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return shares, nil
}

// ListSharesByUser lists shares involving the user (received as recipient + outgoing as owner).
func (c *KeyorixCore) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	received, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	owned, err := c.storage.ListSharesByOwner(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	byID := make(map[uint]*models.ShareRecord)
	for _, s := range received {
		if s != nil {
			byID[s.ID] = s
		}
	}
	for _, s := range owned {
		if s != nil {
			byID[s.ID] = s
		}
	}
	out := make([]*models.ShareRecord, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// CheckSharePermission checks if a user has permission to access a secret.
func (c *KeyorixCore) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	if secretID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.CheckSharePermission(ctx, secretID, userID)
}
