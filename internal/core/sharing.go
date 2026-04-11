package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareSecretRequest represents a request to share a secret with another user or group
type ShareSecretRequest struct {
	SecretID    uint   `json:"secret_id" validate:"required"`
	RecipientID uint   `json:"recipient_id" validate:"required"`
	IsGroup     bool   `json:"is_group"`
	Permission  string `json:"permission" validate:"required,oneof=read write"`
	SharedBy    uint   `json:"shared_by" validate:"required"`
}

// UpdateShareRequest represents a request to update a share's permissions
type UpdateShareRequest struct {
	ShareID    uint   `json:"share_id" validate:"required"`
	Permission string `json:"permission" validate:"required,oneof=read write"`
	UpdatedBy  uint   `json:"updated_by" validate:"required"`
}

// ShareSecret shares a secret with another user or group
func (c *KeyorixCore) ShareSecret(ctx context.Context, req *ShareSecretRequest) (*models.ShareRecord, error) {
	// Validate request
	if err := c.validateShareSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Get the secret to check ownership
	secret, err := c.GetSecret(ctx, req.SecretID)
	if err != nil {
		return nil, err
	}

	// Create share record
	shareRecord := &models.ShareRecord{
		SecretID:    req.SecretID,
		OwnerID:     secret.OwnerID,
		RecipientID: req.RecipientID,
		IsGroup:     req.IsGroup,
		Permission:  req.Permission,
	}

	// Store the share record
	createdShare, err := c.storage.CreateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Log the share creation with enhanced audit logging
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

// UpdateSharePermission updates the permission level of a share
func (c *KeyorixCore) UpdateSharePermission(ctx context.Context, req *UpdateShareRequest) (*models.ShareRecord, error) {
	// Validate request
	if err := c.validateUpdateShareRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Get the share record
	shareRecord, err := c.storage.GetShareRecord(ctx, req.ShareID)
	if err != nil {
		return nil, err
	}

	// Get the secret to check ownership
	secret, err := c.storage.GetSecret(ctx, shareRecord.SecretID)
	if err != nil {
		return nil, err
	}

	// Check if the user owns the secret (only owners can update shares)
	if secret.OwnerID != req.UpdatedBy {
		return nil, fmt.Errorf("%s", i18n.T("ErrorPermissionDenied", nil))
	}

	// Store the old permission for audit logging
	oldPermission := shareRecord.Permission

	// Update the share record
	shareRecord.Permission = req.Permission
	updatedShare, err := c.storage.UpdateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Log the update action with enhanced audit logging
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

// RevokeShare revokes a share
func (c *KeyorixCore) RevokeShare(ctx context.Context, shareID uint, revokedBy uint) error {
	// Get the share record
	shareRecord, err := c.storage.GetShareRecord(ctx, shareID)
	if err != nil {
		return err
	}

	// Get the secret to check ownership
	secret, err := c.storage.GetSecret(ctx, shareRecord.SecretID)
	if err != nil {
		return err
	}

	// Check if the user owns the secret (only owners can revoke shares)
	if secret.OwnerID != revokedBy {
		return fmt.Errorf("%s", i18n.T("ErrorPermissionDenied", nil))
	}

	// Log the revoke action before deletion (we need the share record data)
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

	// Delete the share record
	if err := c.storage.DeleteShareRecord(ctx, shareID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return nil
}

// ListSharedSecrets lists all secrets shared with a user
func (c *KeyorixCore) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// Get shared secrets from storage
	secrets, err := c.storage.ListSharedSecrets(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	return secrets, nil
}

// ListSecretShares lists all shares for a secret
func (c *KeyorixCore) ListSecretShares(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	// Get the secret to check it exists
	_, err := c.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	// Get shares from storage
	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return shares, nil
}

// ListSharesByUser lists shares involving the user: received (recipient) and outgoing (as secret owner on share records).
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

// RemoveSelfFromShare allows a user to remove themselves from a shared secret
func (c *KeyorixCore) RemoveSelfFromShare(ctx context.Context, secretID, userID uint) error {
	if secretID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// Find the share record for this user and secret
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

	// Verify the secret exists for audit logging
	_, err = c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Log the self-removal action before deletion
	auditCtx := &ShareAuditContext{
		ActorID:     userID,
		SecretID:    secretID,
		RecipientID: userID,
		IsGroup:     false,
		Permission:  shareToRemove.Permission,
	}
	c.LogSelfRemovalFromShare(ctx, auditCtx)

	// Delete the share record
	err = c.storage.DeleteShareRecord(ctx, shareToRemove.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return nil
}

// CheckSharePermission checks if a user has permission to access a secret
func (c *KeyorixCore) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	if secretID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// Check permission in storage
	permission, err := c.storage.CheckSharePermission(ctx, secretID, userID)
	if err != nil {
		return "", err
	}

	return permission, nil
}

// Validation methods

func (c *KeyorixCore) validateShareSecretRequest(req *ShareSecretRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.SecretID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.RecipientID == 0 {
		return fmt.Errorf("recipient ID is required")
	}
	if req.Permission != "read" && req.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.SharedBy == 0 {
		return fmt.Errorf("sharedBy is required")
	}
	return nil
}

func (c *KeyorixCore) validateUpdateShareRequest(req *UpdateShareRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.ShareID == 0 {
		return fmt.Errorf("share ID is required")
	}
	if req.Permission != "read" && req.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.UpdatedBy == 0 {
		return fmt.Errorf("updatedBy is required")
	}
	return nil
}

// Helper methods

func (c *KeyorixCore) logShareAction(ctx context.Context, actorID string, action string, secretID, recipientID uint, isGroup bool) {
	recipientType := "user"
	if isGroup {
		recipientType = "group"
	}

	event := &models.AuditEvent{
		EventType:    action,
		Description:  fmt.Sprintf("%s %s secret %d with %s %d", actorID, action, secretID, recipientType, recipientID),
		SecretNodeID: &secretID,
		EventTime:    c.now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}