package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GroupShareSecretRequest represents a request to share a secret with a group
type GroupShareSecretRequest struct {
	SecretID   uint   `json:"secret_id" validate:"required"`
	GroupID    uint   `json:"group_id" validate:"required"`
	Permission string `json:"permission" validate:"required,oneof=read write"`
	SharedBy   uint   `json:"shared_by" validate:"required"`
}

// ShareSecretWithGroup shares a secret with a group
func (c *KeyorixCore) ShareSecretWithGroup(ctx context.Context, req *GroupShareSecretRequest) (*models.ShareRecord, error) {
	// Validate request
	if err := c.validateGroupShareSecretRequest(req); err != nil {
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
		RecipientID: req.GroupID,
		IsGroup:     true,
		Permission:  req.Permission,
	}

	// Validate the group share record
	if err := models.ValidateGroupShare(shareRecord); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Store the share record
	createdShare, err := c.storage.CreateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Log the group share creation with enhanced audit logging
	auditCtx := &ShareAuditContext{
		ActorID:     req.SharedBy,
		SecretID:    secret.ID,
		RecipientID: req.GroupID,
		IsGroup:     true,
		Permission:  req.Permission,
	}
	c.LogGroupShareCreated(ctx, auditCtx)

	return createdShare, nil
}

// ListGroupShares lists all shares for a group
func (c *KeyorixCore) ListGroupShares(ctx context.Context, groupID uint) ([]*models.ShareRecord, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}

	// Get shares from storage
	shares, err := c.storage.ListSharesByGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return shares, nil
}

// ListGroupSharedSecrets lists all secrets shared with a group
func (c *KeyorixCore) ListGroupSharedSecrets(ctx context.Context, groupID uint) ([]*models.SecretNode, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}

	// This would require a new method in the storage interface
	// For now, we'll just return an empty list
	return []*models.SecretNode{}, nil
}

// CheckUserGroupPermission checks if a user has permission to access a secret via group membership
func (c *KeyorixCore) CheckUserGroupPermission(ctx context.Context, secretID, userID uint) (bool, string, error) {
	if secretID == 0 {
		return false, "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return false, "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// This would require a new method in the storage interface
	// For now, we'll just return false
	return false, "", nil
}

// Validation methods

func (c *KeyorixCore) validateGroupShareSecretRequest(req *GroupShareSecretRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.SecretID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.GroupID == 0 {
		return fmt.Errorf("group ID is required")
	}
	if req.Permission != "read" && req.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.SharedBy == 0 {
		return fmt.Errorf("sharedBy is required")
	}
	return nil
}