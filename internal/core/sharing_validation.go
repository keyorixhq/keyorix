// sharing_validation.go — Request validation and logShareAction audit helper.
//
// validateShareSecretRequest, validateUpdateShareRequest, logShareAction.
// Used by sharing.go only.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

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

// logShareAction writes a generic share audit event. Used internally by sharing.go.
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
	_ = c.storage.LogAuditEvent(ctx, event)
}
