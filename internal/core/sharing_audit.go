package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareAuditEvent represents different types of sharing audit events
type ShareAuditEvent string

const (
	// ShareAuditEventCreated represents a share creation event
	ShareAuditEventCreated ShareAuditEvent = "share_created"

	// ShareAuditEventUpdated represents a share permission update event
	ShareAuditEventUpdated ShareAuditEvent = "share_updated"

	// ShareAuditEventRevoked represents a share revocation event
	ShareAuditEventRevoked ShareAuditEvent = "share_revoked"

	// ShareAuditEventAccessed represents a shared secret access event
	ShareAuditEventAccessed ShareAuditEvent = "shared_secret_accessed"

	// ShareAuditEventGroupCreated represents a group share creation event
	ShareAuditEventGroupCreated ShareAuditEvent = "group_share_created"

	// ShareAuditEventGroupUpdated represents a group share permission update event
	ShareAuditEventGroupUpdated ShareAuditEvent = "group_share_updated"

	// ShareAuditEventGroupRevoked represents a group share revocation event
	ShareAuditEventGroupRevoked ShareAuditEvent = "group_share_revoked"

	// ShareAuditEventSelfRemoved represents a user removing themselves from a share
	ShareAuditEventSelfRemoved ShareAuditEvent = "share_self_removed"
)

// ShareAuditContext contains context information for audit logging
type ShareAuditContext struct {
	ActorID       uint
	SecretID      uint
	RecipientID   uint
	IsGroup       bool
	Permission    string
	OldPermission string // For update events
}

// LogShareCreated logs a share creation event
func (c *KeyorixCore) LogShareCreated(ctx context.Context, auditCtx *ShareAuditContext) {
	recipientType := "user"
	if auditCtx.IsGroup {
		recipientType = "group"
	}

	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventCreated),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description:  fmt.Sprintf("Shared with %s %d (permission: %s)", recipientType, auditCtx.RecipientID, auditCtx.Permission),
		EventTime:    time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogShareUpdated logs a share permission update event
func (c *KeyorixCore) LogShareUpdated(ctx context.Context, auditCtx *ShareAuditContext) {
	recipientType := "user"
	if auditCtx.IsGroup {
		recipientType = "group"
	}

	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventUpdated),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description: fmt.Sprintf("Updated share permission for %s %d (from %s to %s)",
			recipientType, auditCtx.RecipientID, auditCtx.OldPermission, auditCtx.Permission),
		EventTime: time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogShareRevoked logs a share revocation event
func (c *KeyorixCore) LogShareRevoked(ctx context.Context, auditCtx *ShareAuditContext) {
	recipientType := "user"
	if auditCtx.IsGroup {
		recipientType = "group"
	}

	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventRevoked),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description:  fmt.Sprintf("Revoked share for %s %d", recipientType, auditCtx.RecipientID),
		EventTime:    time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogSharedSecretAccessed logs when a user accesses a shared secret
func (c *KeyorixCore) LogSharedSecretAccessed(ctx context.Context, auditCtx *ShareAuditContext) {
	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventAccessed),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description:  fmt.Sprintf("Accessed shared secret (permission: %s)", auditCtx.Permission),
		EventTime:    time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogGroupShareCreated logs a group share creation event
func (c *KeyorixCore) LogGroupShareCreated(ctx context.Context, auditCtx *ShareAuditContext) {
	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventGroupCreated),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description:  fmt.Sprintf("Shared with group %d (permission: %s)", auditCtx.RecipientID, auditCtx.Permission),
		EventTime:    time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogGroupShareUpdated logs a group share permission update event
func (c *KeyorixCore) LogGroupShareUpdated(ctx context.Context, auditCtx *ShareAuditContext) {
	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventGroupUpdated),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description: fmt.Sprintf("Updated group share permission for group %d (from %s to %s)",
			auditCtx.RecipientID, auditCtx.OldPermission, auditCtx.Permission),
		EventTime: time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogGroupShareRevoked logs a group share revocation event
func (c *KeyorixCore) LogGroupShareRevoked(ctx context.Context, auditCtx *ShareAuditContext) {
	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventGroupRevoked),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description:  fmt.Sprintf("Revoked group share for group %d", auditCtx.RecipientID),
		EventTime:    time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}

// LogSelfRemovalFromShare logs when a user removes themselves from a shared secret
func (c *KeyorixCore) LogSelfRemovalFromShare(ctx context.Context, auditCtx *ShareAuditContext) {
	event := &models.AuditEvent{
		EventType:    string(ShareAuditEventSelfRemoved),
		UserID:       &auditCtx.ActorID,
		SecretNodeID: &auditCtx.SecretID,
		Description:  fmt.Sprintf("User removed themselves from shared secret (permission: %s)", auditCtx.Permission),
		EventTime:    time.Now(),
	}

	// Log the event (ignore errors to not block the main operation)
	_ = c.storage.LogAuditEvent(ctx, event)
}
