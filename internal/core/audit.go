package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// writeAuditEvent persists an audit_events row.
func (c *KeyorixCore) writeAuditEvent(ctx context.Context, eventType string, userID *uint, secretID *uint, description string) {
	event := &models.AuditEvent{
		EventType:    eventType,
		UserID:       userID,
		SecretNodeID: secretID,
		Description:  description,
		EventTime:    time.Now(),
	}
	_ = c.storage.LogAuditEvent(ctx, event)
}

// writeAccessLog persists a secret_access_logs row.
func (c *KeyorixCore) writeAccessLog(ctx context.Context, secretID uint, accessedBy, action, ip, ua string) {
	log := &models.SecretAccessLog{
		SecretNodeID: secretID,
		AccessedBy:   accessedBy,
		AccessTime:   time.Now(),
		Action:       action,
		IPAddress:    ip,
		UserAgent:    ua,
	}
	_ = c.storage.CreateSecretAccessLog(ctx, log)
}

// LogSecretRead writes audit_events + secret_access_logs for a secret read.
func (c *KeyorixCore) LogSecretRead(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid := userID
	sid := secretID
	c.writeAuditEvent(ctx, "secret.read", &uid, &sid,
		fmt.Sprintf("User %s read secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "read", ip, ua)
}

// LogSecretCreated writes audit_events + secret_access_logs for a secret creation.
func (c *KeyorixCore) LogSecretCreated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid := userID
	sid := secretID
	c.writeAuditEvent(ctx, "secret.created", &uid, &sid,
		fmt.Sprintf("User %s created secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "create", ip, ua)
}

// LogSecretUpdated writes audit_events + secret_access_logs for a secret update.
func (c *KeyorixCore) LogSecretUpdated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid := userID
	sid := secretID
	c.writeAuditEvent(ctx, "secret.updated", &uid, &sid,
		fmt.Sprintf("User %s updated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretDeleted writes audit_events + secret_access_logs for a secret deletion.
func (c *KeyorixCore) LogSecretDeleted(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid := userID
	sid := secretID
	c.writeAuditEvent(ctx, "secret.deleted", &uid, &sid,
		fmt.Sprintf("User %s deleted secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "delete", ip, ua)
}

// LogAuthLogin writes an auth.login audit event.
func (c *KeyorixCore) LogAuthLogin(ctx context.Context, userID uint, username, ip, ua string) {
	uid := userID
	c.writeAuditEvent(ctx, "auth.login", &uid, nil,
		fmt.Sprintf("User %s logged in", username))
}

// LogAuthLogout writes an auth.logout audit event.
func (c *KeyorixCore) LogAuthLogout(ctx context.Context, userID uint, username, ip, ua string) {
	uid := userID
	c.writeAuditEvent(ctx, "auth.logout", &uid, nil,
		fmt.Sprintf("User %s logged out", username))
}

// LookupSessionUser returns the userID and username for a session token.
// Called synchronously before the session is deleted so the data is still available.
// Returns zero values if the session or user cannot be found.
func (c *KeyorixCore) LookupSessionUser(ctx context.Context, token string) (userID uint, username string) {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return 0, ""
	}
	user, err := c.storage.GetUser(ctx, session.UserID)
	if err != nil {
		return session.UserID, ""
	}
	return user.ID, user.Username
}
