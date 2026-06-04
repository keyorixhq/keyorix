package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// writeAuditEvent persists an audit_events row (basic — no project/IP context).
func (c *KeyorixCore) writeAuditEvent(ctx context.Context, eventType string, userID *uint, secretID *uint, description string) {
	c.writeAuditEventFull(ctx, eventType, userID, secretID, nil, "", description)
}

// writeAuditEventFull persists an audit_events row with full NIS2/DORA context.
func (c *KeyorixCore) writeAuditEventFull(ctx context.Context, eventType string, userID *uint, secretID *uint, projectID *uint, ip string, description string) {
	c.writeAuditEventDiff(ctx, eventType, userID, secretID, projectID, ip, description, "")
}

// writeAuditEventDiff is writeAuditEventFull plus a structured before/after diff.
// It also stamps impersonation attribution when the context carries an
// impersonation tag (set by the auth middleware), so every action taken inside
// an impersonation session is consistently marked with impersonation=true.
func (c *KeyorixCore) writeAuditEventDiff(ctx context.Context, eventType string, userID *uint, secretID *uint, projectID *uint, ip string, description string, diff string) {
	t := true
	event := &models.AuditEvent{
		EventType:    eventType,
		UserID:       userID,
		SecretNodeID: secretID,
		ProjectID:    projectID,
		IPAddress:    ip,
		Description:  description,
		Success:      &t,
		EventTime:    time.Now(),
		Diff:         diff,
	}
	if adminID, ok := impersonatorFromContext(ctx); ok {
		a := adminID
		event.ImpersonatedBy = &a
		event.ActingAs = userID
		event.Impersonation = true
	}
	c.emitAudit(ctx, event)
}

// writeAuditEventFailed persists a failed audit event (Success=false).
func (c *KeyorixCore) writeAuditEventFailed(ctx context.Context, eventType string, userID *uint, ip string, description string) {
	f := false
	event := &models.AuditEvent{
		EventType:   eventType,
		UserID:      userID,
		IPAddress:   ip,
		Description: description,
		Success:     &f,
		EventTime:   time.Now(),
	}
	c.emitAudit(ctx, event)
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
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.read", &uid, &sid,
		fmt.Sprintf("User %s read secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "read", ip, ua)
}

// LogSecretReadWithProject writes audit_events + secret_access_logs including project context.
func (c *KeyorixCore) LogSecretReadWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) {
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.read", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s read secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "read", ip, ua)
}

// LogSecretCreated writes audit_events + secret_access_logs for a secret creation.
func (c *KeyorixCore) LogSecretCreated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.created", &uid, &sid,
		fmt.Sprintf("User %s created secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "create", ip, ua)
}

// LogSecretCreatedWithProject writes audit_events + secret_access_logs including project context.
func (c *KeyorixCore) LogSecretCreatedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) {
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.created", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s created secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "create", ip, ua)
}

// LogSecretUpdated writes audit_events + secret_access_logs for a secret update.
func (c *KeyorixCore) LogSecretUpdated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.updated", &uid, &sid,
		fmt.Sprintf("User %s updated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretUpdatedWithProject writes audit_events including project context.
func (c *KeyorixCore) LogSecretUpdatedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) {
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.updated", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s updated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretUpdatedWithDiff writes a secret.updated audit event carrying a
// structured before/after diff (see audit_diff.go — never includes plaintext
// values) plus the secret_access_logs row.
func (c *KeyorixCore) LogSecretUpdatedWithDiff(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua, diff string) {
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventDiff(ctx, "secret.updated", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s updated secret %s", username, secretName), diff)
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretDeleted writes audit_events + secret_access_logs for a secret deletion.
func (c *KeyorixCore) LogSecretDeleted(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.deleted", &uid, &sid,
		fmt.Sprintf("User %s deleted secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "delete", ip, ua)
}

// LogSecretDeletedWithProject writes audit_events including project context.
func (c *KeyorixCore) LogSecretDeletedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) {
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.deleted", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s deleted secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "delete", ip, ua)
}

// LogAuthLogin writes an auth.login audit event.
func (c *KeyorixCore) LogAuthLogin(ctx context.Context, userID uint, username, ip, ua string) {
	uid := userID
	c.writeAuditEventFull(ctx, "auth.login", &uid, nil, nil, ip,
		fmt.Sprintf("User %s logged in", username))
}

// LogAuthFailure writes an auth.login_failed audit event (Success=false).
func (c *KeyorixCore) LogAuthFailure(ctx context.Context, username, ip string) {
	c.writeAuditEventFailed(ctx, "auth.login_failed", nil, ip,
		fmt.Sprintf("Failed login attempt for username: %s", username))
}

// LogAuthLogout writes an auth.logout audit event.
func (c *KeyorixCore) LogAuthLogout(ctx context.Context, userID uint, username, ip, ua string) {
	uid := userID
	c.writeAuditEventFull(ctx, "auth.logout", &uid, nil, nil, ip,
		fmt.Sprintf("User %s logged out", username))
}

// LookupSessionUser returns the userID and username for a session token.
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
