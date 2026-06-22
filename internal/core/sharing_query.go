// sharing_query.go — ListSharedSecrets, ListSecretShares, ListSharesByUser, CheckSharePermission.
//
// Read-only query operations over share records.
// For share create/update/revoke see sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"
	"time"

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
	// Drop expired time-bound shares so the list matches what actually authorizes
	// (every enforcement path filters via activeShares); they're swept separately.
	return activeShares(shares, c.now()), nil
}

// ListSecretSharesWithPermissionCheck lists a secret's shares, but only for its
// owner — the share list (recipients, permission levels) is owner-only, matching
// UpdateSharePermission/RevokeShare. Without this, any caller with secrets.read
// could enumerate who has access to any secret. Authenticated request surfaces
// (HTTP/gRPC) use this; the local CLI uses ListSecretShares directly.
func (c *KeyorixCore) ListSecretSharesWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]*models.ShareRecord, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if !secretOwnedBy(secret.OwnerID, userID) {
		return nil, fmt.Errorf("not authorized to view shares for this secret")
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Drop expired time-bound shares — see ListSecretShares.
	return activeShares(shares, c.now()), nil
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

// ShareView is an enriched, transport-ready share record: recipient and creator are
// resolved to display names and the JSON is camelCase to match the web client (which
// consumes the /shares list verbatim, without field mapping).
type ShareView struct {
	ID            uint       `json:"id"`
	SecretID      uint       `json:"secretId"`
	RecipientType string     `json:"recipientType"` // "user" | "group"
	RecipientID   uint       `json:"recipientId"`
	RecipientName string     `json:"recipientName"`
	Permission    string     `json:"permission"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"` // nil = permanent (time-bound shares)
	CreatedAt     time.Time  `json:"createdAt"`
	CreatedBy     string     `json:"createdBy"` // username of the share's owner
}

// ListUserShareViews returns the user's shares (received + owned) as enriched views
// with recipient/creator names resolved, ready to serialise for the web sharing UI.
func (c *KeyorixCore) ListUserShareViews(ctx context.Context, userID uint) ([]ShareView, error) {
	shares, err := c.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	userNames := map[uint]string{}
	resolveUser := func(id uint) string {
		if id == 0 {
			return ""
		}
		if n, ok := userNames[id]; ok {
			return n
		}
		name := fmt.Sprintf("User %d", id)
		if u, err := c.storage.GetUser(ctx, id); err == nil && u != nil && u.Username != "" {
			name = u.Username
		}
		userNames[id] = name
		return name
	}
	groupNames := map[uint]string{}
	resolveGroup := func(id uint) string {
		if n, ok := groupNames[id]; ok {
			return n
		}
		name := fmt.Sprintf("Group %d", id)
		if g, err := c.storage.GetGroup(ctx, id); err == nil && g != nil && g.Name != "" {
			name = g.Name
		}
		groupNames[id] = name
		return name
	}

	views := make([]ShareView, 0, len(shares))
	for _, s := range shares {
		v := ShareView{
			ID:          s.ID,
			SecretID:    s.SecretID,
			RecipientID: s.RecipientID,
			Permission:  s.Permission,
			ExpiresAt:   s.ExpiresAt,
			CreatedAt:   s.CreatedAt,
			CreatedBy:   resolveUser(s.OwnerID),
		}
		if s.IsGroup {
			v.RecipientType = "group"
			v.RecipientName = resolveGroup(s.RecipientID)
		} else {
			v.RecipientType = "user"
			v.RecipientName = resolveUser(s.RecipientID)
		}
		views = append(views, v)
	}
	return views, nil
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
