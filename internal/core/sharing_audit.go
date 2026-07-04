package core

import (
	"context"
	"fmt"
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

	desc := fmt.Sprintf("Shared with %s %d (permission: %s)", recipientType, auditCtx.RecipientID, auditCtx.Permission)
	// Route through the shared choke point so impersonation context
	// (ActorType/ImpersonatedBy/ActingAs/Impersonation) gets stamped consistently (#284).
	c.writeAuditEvent(ctx, string(ShareAuditEventCreated), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogShareUpdated logs a share permission update event
func (c *KeyorixCore) LogShareUpdated(ctx context.Context, auditCtx *ShareAuditContext) {
	recipientType := "user"
	if auditCtx.IsGroup {
		recipientType = "group"
	}

	desc := fmt.Sprintf("Updated share permission for %s %d (from %s to %s)",
		recipientType, auditCtx.RecipientID, auditCtx.OldPermission, auditCtx.Permission)
	c.writeAuditEvent(ctx, string(ShareAuditEventUpdated), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogShareRevoked logs a share revocation event
func (c *KeyorixCore) LogShareRevoked(ctx context.Context, auditCtx *ShareAuditContext) {
	recipientType := "user"
	if auditCtx.IsGroup {
		recipientType = "group"
	}

	desc := fmt.Sprintf("Revoked share for %s %d", recipientType, auditCtx.RecipientID)
	c.writeAuditEvent(ctx, string(ShareAuditEventRevoked), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogGroupShareCreated logs a group share creation event
func (c *KeyorixCore) LogGroupShareCreated(ctx context.Context, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("Shared with group %d (permission: %s)", auditCtx.RecipientID, auditCtx.Permission)
	c.writeAuditEvent(ctx, string(ShareAuditEventGroupCreated), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogGroupShareUpdated logs a group share permission update event
func (c *KeyorixCore) LogGroupShareUpdated(ctx context.Context, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("Updated group share permission for group %d (from %s to %s)",
		auditCtx.RecipientID, auditCtx.OldPermission, auditCtx.Permission)
	c.writeAuditEvent(ctx, string(ShareAuditEventGroupUpdated), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogGroupShareRevoked logs a group share revocation event
func (c *KeyorixCore) LogGroupShareRevoked(ctx context.Context, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("Revoked group share for group %d", auditCtx.RecipientID)
	c.writeAuditEvent(ctx, string(ShareAuditEventGroupRevoked), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogSelfRemovalFromShare logs when a user removes themselves from a shared secret
func (c *KeyorixCore) LogSelfRemovalFromShare(ctx context.Context, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("User removed themselves from shared secret (permission: %s)", auditCtx.Permission)
	c.writeAuditEvent(ctx, string(ShareAuditEventSelfRemoved), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}
