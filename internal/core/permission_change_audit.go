// permission_change_audit.go — structured before/after diff of permission changes
// (role grants/revokes) surfaced from the existing audit event trail.
//
// GetPermissionChangeAudit queries audit_events for role assignment/removal
// actions and returns them as PermissionChangeEvent records with resolved actor
// and role names, bounded by a time window and a per-call limit.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// permChangeEventTypes is the subset of RBAC audit event types that represent
// a direct permission change to a user (role grant or revoke). Group membership
// and permission-to-role changes are excluded: they change effective permissions
// indirectly and are already covered by the full RBAC audit trail
// (ListRBACAuditLogs).
var permChangeEventTypes = []string{
	EventRoleAssigned,
	EventRoleRemoved,
	EventRoleExpired,
}

const (
	permChangeDefaultLimit  = 100
	permChangeMaxLimit      = 1000
	permChangeDefaultWindow = 30 * 24 * time.Hour
)

// PermissionChangeEvent represents a single role grant or revoke event.
type PermissionChangeEvent struct {
	EventID    uint      `json:"event_id"`
	Action     string    `json:"action"`      // "role.assigned" | "role.removed" | "role.expired"
	ActorName  string    `json:"actor_name"`  // who made the change (empty = system/CLI)
	TargetUser string    `json:"target_user"` // whose permissions changed (username or "user:<id>")
	RoleName   string    `json:"role_name"`   // role name, or "role:<id>" if lookup fails
	Scope      string    `json:"scope"`       // "global" or "project:<id>"
	ChangedAt  time.Time `json:"changed_at"`
}

// PermissionChangeReport is the structured diff of permission changes over a
// time window.
type PermissionChangeReport struct {
	Since   time.Time               `json:"since"`
	Until   time.Time               `json:"until"`
	Changes []PermissionChangeEvent `json:"changes"`
	Total   int                     `json:"total"`
	// Truncated is true when more matching events exist than the bounded limit
	// returned — Changes/len(Changes) then reflect only the first page, not the
	// true total (#G24: previously Total silently reported len(Changes), the
	// truncated sample size, as if it were the real total).
	Truncated bool `json:"truncated"`
}

// normPermChangeWindow normalises the since/until/limit parameters, filling in defaults.
//
// since/until are also UTC-normalized here (G81, third recurrence, read side)
// even though GetAuditLogs already normalizes its own filter bounds — a
// caller-supplied non-zero value skips the defaulting branches below and
// would otherwise reach GetAuditLogs un-normalized until it, too, is checked.
// Redundant with GetAuditLogs' own normalization for the default-window case,
// but correct by construction is cheap here.
func normPermChangeWindow(since, until time.Time, limit int) (time.Time, time.Time, int) {
	now := time.Now().UTC()
	if since.IsZero() {
		since = now.Add(-permChangeDefaultWindow)
	} else {
		since = since.UTC()
	}
	if until.IsZero() {
		until = now
	} else {
		until = until.UTC()
	}
	if limit <= 0 {
		limit = permChangeDefaultLimit
	}
	if limit > permChangeMaxLimit {
		limit = permChangeMaxLimit
	}
	return since, until, limit
}

// resolvePermChangeActorName resolves the actor username for an audit event.
// Returns an empty string when the actor is the system or unknown.
func (k *KeyorixCore) resolvePermChangeActorName(ctx context.Context, userID *uint) string {
	if userID == nil || *userID == 0 {
		return ""
	}
	if u, err := k.storage.GetUser(ctx, *userID); err == nil {
		return u.Username
	}
	return ""
}

// resolvePermChangeTarget resolves the target user name from detail.TargetUserID.
// Falls back to "user:<id>" when the user row is gone.
func (k *KeyorixCore) resolvePermChangeTarget(ctx context.Context, targetUserID uint) string {
	if targetUserID == 0 {
		return ""
	}
	if u, err := k.storage.GetUser(ctx, targetUserID); err == nil {
		return u.Username
	}
	return fmt.Sprintf("user:%d", targetUserID)
}

// resolvePermChangeRole resolves the role name from detail.RoleID.
// Falls back to "role:<id>" when the role row is gone.
func (k *KeyorixCore) resolvePermChangeRole(ctx context.Context, roleID uint) string {
	if roleID == 0 {
		return ""
	}
	if r, err := k.storage.GetRole(ctx, roleID); err == nil {
		return r.Name
	}
	return fmt.Sprintf("role:%d", roleID)
}

// buildPermChangeEvent converts a raw audit event into a PermissionChangeEvent.
func (k *KeyorixCore) buildPermChangeEvent(ctx context.Context, e *models.AuditEvent) PermissionChangeEvent {
	var detail rbacAuditDetail
	if e.Diff != "" {
		_ = json.Unmarshal([]byte(e.Diff), &detail)
	}

	scope := "global"
	if detail.ProjectID != 0 {
		scope = fmt.Sprintf("project:%d", detail.ProjectID)
	}

	return PermissionChangeEvent{
		EventID:    e.ID,
		Action:     e.EventType,
		ActorName:  k.resolvePermChangeActorName(ctx, e.UserID),
		TargetUser: k.resolvePermChangeTarget(ctx, detail.TargetUserID),
		RoleName:   k.resolvePermChangeRole(ctx, detail.RoleID),
		Scope:      scope,
		ChangedAt:  e.EventTime,
	}
}

// GetPermissionChangeAudit returns structured permission change events between
// since and until, limited to at most limit entries (default 100, max 1000).
// If since is zero it defaults to 30 days ago; if until is zero it defaults to
// now. Results are returned chronologically (oldest first).
func (k *KeyorixCore) GetPermissionChangeAudit(ctx context.Context, since, until time.Time, limit int) (*PermissionChangeReport, error) {
	since, until, limit = normPermChangeWindow(since, until, limit)

	filter := &storage.AuditFilter{
		Actions:   permChangeEventTypes,
		StartTime: &since,
		EndTime:   &until,
		Ascending: true,
		PageSize:  limit,
		Page:      1,
	}

	events, total, err := k.storage.GetAuditLogs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("permission_change_audit: query failed: %w", err)
	}

	changes := make([]PermissionChangeEvent, 0, len(events))
	for _, e := range events {
		changes = append(changes, k.buildPermChangeEvent(ctx, e))
	}

	return &PermissionChangeReport{
		Since:     since,
		Until:     until,
		Changes:   changes,
		Total:     int(total),
		Truncated: int64(len(changes)) < total,
	}, nil
}
