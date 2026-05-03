// sharing.go — ShareSecret, UpdateSharePermission, RevokeShare, RemoveSelfFromShare.
//
// Request types also live here (ShareSecretRequest, UpdateShareRequest).
// For list/query operations see sharing_query.go.
// For validation helpers see sharing_validation.go.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareSecretRequest represents a request to share a secret with another user or group.
type ShareSecretRequest struct {
	SecretID    uint   `json:"secret_id" validate:"required"`
	RecipientID uint   `json:"recipient_id" validate:"required"`
	IsGroup     bool   `json:"is_group"`
	Permission  string `json:"permission" validate:"required,oneof=read write"`
	SharedBy    uint   `json:"shared_by" validate:"required"`
}

// UpdateShareRequest represents a request to update a share's permissions.
type UpdateShareRequest struct {
	ShareID    uint   `json:"share_id" validate:"required"`
	Permission string `json:"permission" validate:"required,oneof=read write"`
	UpdatedBy  uint   `json:"updated_by" validate:"required"`
}

// ShareSecret shares a secret with another user or group.
func (c *KeyorixCore) ShareSecret(ctx context.Context, req *ShareSecretRequest) (*models.ShareRecord, error) {
	if err := c.validateShareSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	secret, err := c.GetSecret(ctx, req.SecretID)
	if err != nil {
		return nil, err
	}

	shareRecord := &models.ShareRecord{
		SecretID:    req.SecretID,
		OwnerID:     secret.OwnerID,
		RecipientID: req.RecipientID,
		IsGroup:     req.IsGroup,
		Permission:  req.Permission,
	}
	createdShare, err := c.storage.CreateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	auditCtx := &ShareAuditContext{
		ActorID:     req.SharedBy,
		SecretID:    secret.ID,
		RecipientID: req.RecipientID,
		IsGroup:     req.IsGroup,
		Permission:  req.Permission,
	}
	if req.IsGroup {
		c.LogGroupShareCreated(ctx, auditCtx)
	} else {
		c.LogShareCreated(ctx, auditCtx)
	}

	return createdShare, nil
}

// UpdateSharePermission updates the permission level of an existing share.
func (c *KeyorixCore) UpdateSharePermission(ctx context.Context, req *UpdateShareRequest) (*models.ShareRecord, error) {
	if err := c.validateUpdateShareRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	shareRecord, err := c.storage.GetShareRecord(ctx, req.ShareID)
	if err != nil {
		return nil, err
	}

	secret, err := c.storage.GetSecret(ctx, shareRecord.SecretID)
	if err != nil {
		return nil, err
	}
	if secret.OwnerID != req.UpdatedBy {
		return nil, fmt.Errorf("%s", i18n.T("ErrorPermissionDenied", nil))
	}

	oldPermission := shareRecord.Permission
	shareRecord.Permission = req.Permission
	updatedShare, err := c.storage.UpdateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	auditCtx := &ShareAuditContext{
		ActorID:       req.UpdatedBy,
		SecretID:      updatedShare.SecretID,
		RecipientID:   updatedShare.RecipientID,
		IsGroup:       updatedShare.IsGroup,
		Permission:    updatedShare.Permission,
		OldPermission: oldPermission,
	}
	if updatedShare.IsGroup {
		c.LogGroupShareUpdated(ctx, auditCtx)
	} else {
		c.LogShareUpdated(ctx, auditCtx)
	}

	return updatedShare, nil
}

// RevokeShare revokes a share. Only the secret owner can revoke.
func (c *KeyorixCore) RevokeShare(ctx context.Context, shareID uint, revokedBy uint) error {
	shareRecord, err := c.storage.GetShareRecord(ctx, shareID)
	if err != nil {
		return err
	}

	secret, err := c.storage.GetSecret(ctx, shareRecord.SecretID)
	if err != nil {
		return err
	}
	if secret.OwnerID != revokedBy {
		return fmt.Errorf("%s", i18n.T("ErrorPermissionDenied", nil))
	}

	auditCtx := &ShareAuditContext{
		ActorID:     revokedBy,
		SecretID:    shareRecord.SecretID,
		RecipientID: shareRecord.RecipientID,
		IsGroup:     shareRecord.IsGroup,
		Permission:  shareRecord.Permission,
	}
	if shareRecord.IsGroup {
		c.LogGroupShareRevoked(ctx, auditCtx)
	} else {
		c.LogShareRevoked(ctx, auditCtx)
	}

	if err := c.storage.DeleteShareRecord(ctx, shareID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveSelfFromShare allows a user to remove themselves from a shared secret.
func (c *KeyorixCore) RemoveSelfFromShare(ctx context.Context, secretID, userID uint) error {
	if secretID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var shareToRemove *models.ShareRecord
	for _, share := range shares {
		if !share.IsGroup && share.RecipientID == userID {
			shareToRemove = share
			break
		}
	}
	if shareToRemove == nil {
		return fmt.Errorf("%s", i18n.T("ErrorShareNotFound", nil))
	}

	if _, err = c.storage.GetSecret(ctx, secretID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	c.LogSelfRemovalFromShare(ctx, &ShareAuditContext{
		ActorID:     userID,
		SecretID:    secretID,
		RecipientID: userID,
		IsGroup:     false,
		Permission:  shareToRemove.Permission,
	})

	if err := c.storage.DeleteShareRecord(ctx, shareToRemove.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}
