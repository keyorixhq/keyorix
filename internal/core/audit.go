package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RBAC audit event types. Role assignments/removals are written to the shared
// audit_events table and surfaced together by ListRBACAuditLogs.
const (
	EventRoleAssigned      = "role.assigned"
	EventRoleRemoved       = "role.removed"
	EventRoleExpired       = "role.expired"        // #nosec G101 -- audit event type, not a credential
	EventRoleGroupAssigned = "role.group_assigned" // #nosec G101 -- audit event type, not a credential
	EventRoleGroupRemoved  = "role.group_removed"  // #nosec G101 -- audit event type, not a credential
	EventPermissionAdded   = "permission.assigned" // #nosec G101 -- audit event type, not a credential
	EventPermissionRemoved = "permission.removed"  // #nosec G101 -- audit event type, not a credential
	// Role-definition lifecycle (the role itself, not an assignment of it).
	EventRoleCreated = "role.created"
	EventRoleUpdated = "role.updated"
	EventRoleDeleted = "role.deleted"
)

// rbacAuditEventTypes is the set of event types that make up the RBAC audit log.
var rbacAuditEventTypes = []string{
	EventRoleAssigned, EventRoleRemoved, EventRoleExpired,
	EventRoleGroupAssigned, EventRoleGroupRemoved,
	EventPermissionAdded, EventPermissionRemoved,
	EventRoleCreated, EventRoleUpdated, EventRoleDeleted,
}

// rbacAuditDetail is the structured payload stored in an RBAC event's Diff field,
// carrying the target/role/scope that the generic AuditEvent row cannot.
type rbacAuditDetail struct {
	TargetUserID  uint `json:"target_user_id,omitempty"`
	GroupID       uint `json:"group_id,omitempty"`
	RoleID        uint `json:"role_id"`
	PermissionID  uint `json:"permission_id,omitempty"`
	ProjectID     uint `json:"project_id,omitempty"`
	EnvironmentID uint `json:"environment_id,omitempty"`
}

// LogRoleAssigned / LogRoleRemoved record an RBAC change. actorID is the user who
// made the change (0 = no authenticated principal, e.g. a local CLI invocation);
// the target/role/scope are captured in the event's structured diff.
func (c *KeyorixCore) LogRoleAssigned(ctx context.Context, actorID, targetUserID, roleID uint, scope Scope) {
	c.logRoleChange(ctx, EventRoleAssigned, "assigned to", actorID, targetUserID, roleID, scope)
}

func (c *KeyorixCore) LogRoleRemoved(ctx context.Context, actorID, targetUserID, roleID uint, scope Scope) {
	c.logRoleChange(ctx, EventRoleRemoved, "removed from", actorID, targetUserID, roleID, scope)
}

func (c *KeyorixCore) logRoleChange(ctx context.Context, eventType, verb string, actorID, targetUserID, roleID uint, scope Scope) {
	desc := fmt.Sprintf("role %d %s user %d", roleID, verb, targetUserID)
	c.writeRBACAudit(ctx, eventType, desc, actorID, scope, rbacAuditDetail{
		TargetUserID:  targetUserID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
	})
}

// LogGroupRoleAssigned / LogGroupRoleRemoved record a role granted to / removed
// from a group. See LogRoleAssigned for actorID semantics.
func (c *KeyorixCore) LogGroupRoleAssigned(ctx context.Context, actorID, groupID, roleID uint, scope Scope) {
	c.logGroupRoleChange(ctx, EventRoleGroupAssigned, "assigned to group", actorID, groupID, roleID, scope)
}

func (c *KeyorixCore) LogGroupRoleRemoved(ctx context.Context, actorID, groupID, roleID uint, scope Scope) {
	c.logGroupRoleChange(ctx, EventRoleGroupRemoved, "removed from group", actorID, groupID, roleID, scope)
}

func (c *KeyorixCore) logGroupRoleChange(ctx context.Context, eventType, verb string, actorID, groupID, roleID uint, scope Scope) {
	desc := fmt.Sprintf("role %d %s %d", roleID, verb, groupID)
	c.writeRBACAudit(ctx, eventType, desc, actorID, scope, rbacAuditDetail{
		GroupID:       groupID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
	})
}

// LogPermissionAssigned / LogPermissionRemoved record a permission granted to /
// removed from a role. See LogRoleAssigned for actorID semantics.
func (c *KeyorixCore) LogPermissionAssigned(ctx context.Context, actorID, roleID, permissionID uint) {
	c.logPermissionChange(ctx, EventPermissionAdded, "granted to role", actorID, roleID, permissionID)
}

func (c *KeyorixCore) LogPermissionRemoved(ctx context.Context, actorID, roleID, permissionID uint) {
	c.logPermissionChange(ctx, EventPermissionRemoved, "removed from role", actorID, roleID, permissionID)
}

func (c *KeyorixCore) logPermissionChange(ctx context.Context, eventType, verb string, actorID, roleID, permissionID uint) {
	desc := fmt.Sprintf("permission %d %s %d", permissionID, verb, roleID)
	c.writeRBACAudit(ctx, eventType, desc, actorID, Scope{}, rbacAuditDetail{
		RoleID:       roleID,
		PermissionID: permissionID,
	})
}

// LogRoleCreated / LogRoleUpdated / LogRoleDeleted record a change to a role
// DEFINITION (distinct from assigning a role to a principal). Role definitions are
// global, so no scope. actorID is the admin who made the change (0 = no
// authenticated principal). They surface in the RBAC audit log alongside grants.
func (c *KeyorixCore) LogRoleCreated(ctx context.Context, actorID, roleID uint, name string) {
	c.logRoleDefinitionChange(ctx, EventRoleCreated, "created", actorID, roleID, name)
}

func (c *KeyorixCore) LogRoleUpdated(ctx context.Context, actorID, roleID uint, name string) {
	c.logRoleDefinitionChange(ctx, EventRoleUpdated, "updated", actorID, roleID, name)
}

func (c *KeyorixCore) LogRoleDeleted(ctx context.Context, actorID, roleID uint, name string) {
	c.logRoleDefinitionChange(ctx, EventRoleDeleted, "deleted", actorID, roleID, name)
}

func (c *KeyorixCore) logRoleDefinitionChange(ctx context.Context, eventType, verb string, actorID, roleID uint, name string) {
	desc := fmt.Sprintf("role %q (id %d) %s", name, roleID, verb)
	c.writeRBACAudit(ctx, eventType, desc, actorID, Scope{}, rbacAuditDetail{RoleID: roleID})
}

// writeRBACAudit is the shared writer for RBAC audit events: actor as UserID,
// scope's project as ProjectID, and the structured detail in the diff.
func (c *KeyorixCore) writeRBACAudit(ctx context.Context, eventType, desc string, actorID uint, scope Scope, detail rbacAuditDetail) {
	encoded, _ := json.Marshal(detail)
	var actor *uint
	if actorID != 0 {
		a := actorID
		actor = &a
	}
	var projectID *uint
	if scope.ProjectID != 0 {
		p := scope.ProjectID
		projectID = &p
	}
	c.writeAuditEventDiff(ctx, eventType, actor, nil, projectID, "", desc, string(encoded))
}

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
		Description:  sanitizeAuditText(description),
		Success:      &t,
		EventTime:    time.Now(),
		Diff:         diff,
		ActorType:    actorTypeFromContext(ctx),
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
		Description: sanitizeAuditText(description),
		Success:     &f,
		EventTime:   time.Now(),
		ActorType:   actorTypeFromContext(ctx),
	}
	c.emitAudit(ctx, event)
}

// sanitizeAuditText strips control characters (CR/LF, ANSI/C1 escapes, NUL, etc.) from a
// string headed for an audit Description, so a crafted secret name or username can't inject
// a forged audit line or smuggle terminal-control sequences into a CLI audit viewer. The
// audit chain hashes the Description, so cleaning it also keeps the persisted, tamper-
// evident content faithful. A tab is normalized to a space; other controls are dropped.
func sanitizeAuditText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1 // drop
		}
		return r
	}, s)
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

// LogSecretRotated writes audit_events + secret_access_logs for a secret rotation.
func (c *KeyorixCore) LogSecretRotated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.rotated", &uid, &sid,
		fmt.Sprintf("User %s rotated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "rotate", ip, ua)
}

// LogSecretRotatedWithProject writes audit_events + secret_access_logs including project context.
func (c *KeyorixCore) LogSecretRotatedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) {
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.rotated", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s rotated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "rotate", ip, ua)
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
