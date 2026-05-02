package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PermissionLevel represents the level of access a user has to a secret.
type PermissionLevel string

const (
	PermissionNone  PermissionLevel = "none"
	PermissionRead  PermissionLevel = "read"
	PermissionWrite PermissionLevel = "write"
	PermissionOwner PermissionLevel = "owner"
)

// PermissionContext contains information about a user's permission for a secret.
type PermissionContext struct {
	SecretID   uint
	UserID     uint
	Permission PermissionLevel
	Source     string // "owner", "direct_share", "group_share"
	ShareID    *uint  // ID of the share record if applicable
}

// CheckSecretPermission checks if a user has the required permission for a secret.
func (c *KeyorixCore) CheckSecretPermission(ctx context.Context, secretID, userID uint, requiredPermission PermissionLevel) (*PermissionContext, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// Owners have all permissions.
	if secret.OwnerID == userID {
		return &PermissionContext{
			SecretID:   secretID,
			UserID:     userID,
			Permission: PermissionOwner,
			Source:     "owner",
		}, nil
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// Check direct shares.
	for _, share := range shares {
		if !share.IsGroup && share.RecipientID == userID {
			permission := PermissionLevel(share.Permission)
			if c.hasRequiredPermission(permission, requiredPermission) {
				return &PermissionContext{
					SecretID:   secretID,
					UserID:     userID,
					Permission: permission,
					Source:     "direct_share",
					ShareID:    &share.ID,
				}, nil
			}
		}
	}

	// Check group shares.
	groupPermission, shareID, err := c.CheckGroupPermissions(ctx, secretID, userID, shares)
	if err == nil && groupPermission != PermissionNone {
		if c.hasRequiredPermission(groupPermission, requiredPermission) {
			return &PermissionContext{
				SecretID:   secretID,
				UserID:     userID,
				Permission: groupPermission,
				Source:     "group_share",
				ShareID:    shareID,
			}, nil
		}
	}

	return nil, fmt.Errorf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
}

// hasRequiredPermission checks if the user's permission level meets the required level.
func (c *KeyorixCore) hasRequiredPermission(userPermission, requiredPermission PermissionLevel) bool {
	permissionLevels := map[PermissionLevel]int{
		PermissionNone:  0,
		PermissionRead:  1,
		PermissionWrite: 2,
		PermissionOwner: 3,
	}
	userLevel, exists := permissionLevels[userPermission]
	if !exists {
		return false
	}
	requiredLevel, exists := permissionLevels[requiredPermission]
	if !exists {
		return false
	}
	return userLevel >= requiredLevel
}

// CheckGroupPermissions checks if a user has permission through group membership.
func (c *KeyorixCore) CheckGroupPermissions(ctx context.Context, secretID, userID uint, shares []*models.ShareRecord) (PermissionLevel, *uint, error) {
	userGroups, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		return PermissionNone, nil, err
	}

	var highestPermission PermissionLevel = PermissionNone
	var shareID *uint

	for _, share := range shares {
		if share.IsGroup {
			for _, group := range userGroups {
				if group.ID == share.RecipientID {
					permission := PermissionLevel(share.Permission)
					if c.hasRequiredPermission(permission, highestPermission) {
						highestPermission = permission
						shareID = &share.ID
					}
				}
			}
		}
	}

	return highestPermission, shareID, nil
}

// EnforceSecretReadPermission enforces read permission for secret operations.
func (c *KeyorixCore) EnforceSecretReadPermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionRead)
}

// EnforceSecretWritePermission enforces write permission for secret operations.
func (c *KeyorixCore) EnforceSecretWritePermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionWrite)
}

// EnforceSecretOwnerPermission enforces owner permission for secret operations.
func (c *KeyorixCore) EnforceSecretOwnerPermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionOwner)
}

// ValidateSecretAccess validates that a user can access a secret (requires at least read).
func (c *KeyorixCore) ValidateSecretAccess(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.EnforceSecretReadPermission(ctx, secretID, userID)
}

// CanUserModifySecret checks if a user can modify a secret (requires write or owner permission).
func (c *KeyorixCore) CanUserModifySecret(ctx context.Context, secretID, userID uint) (bool, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionWrite)
	if err != nil {
		return false, nil
	}
	return permCtx != nil, nil
}

// CanUserShareSecret checks if a user can share a secret (requires owner permission).
func (c *KeyorixCore) CanUserShareSecret(ctx context.Context, secretID, userID uint) (bool, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionOwner)
	if err != nil {
		return false, nil
	}
	return permCtx != nil, nil
}

// GetEffectivePermission returns the effective permission level for a user on a secret.
func (c *KeyorixCore) GetEffectivePermission(ctx context.Context, secretID, userID uint) (PermissionLevel, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionRead)
	if err != nil {
		return PermissionNone, nil
	}
	return permCtx.Permission, nil
}

// ListUserPermissions returns all secrets a user has access to with their permission levels.
func (c *KeyorixCore) ListUserPermissions(ctx context.Context, userID uint) ([]*models.UserSecretPermission, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	var permissions []*models.UserSecretPermission

	ownedSecrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &[]string{fmt.Sprintf("%d", userID)}[0],
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, secret := range ownedSecrets {
		permissions = append(permissions, &models.UserSecretPermission{
			SecretID:   secret.ID,
			UserID:     userID,
			Permission: string(PermissionOwner),
			Source:     "owner",
		})
	}

	directShares, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, share := range directShares {
		permissions = append(permissions, &models.UserSecretPermission{
			SecretID:   share.SecretID,
			UserID:     userID,
			Permission: share.Permission,
			Source:     "direct_share",
			ShareID:    &share.ID,
		})
	}

	// TODO: include group-shared secrets when group functionality is fully wired.

	return permissions, nil
}
