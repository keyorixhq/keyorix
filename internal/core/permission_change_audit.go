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
}

// GetPermissionChangeAudit returns structured permission change events between
// since and until, limited to at most limit entries (default 100, max 1000).
// If since is zero it defaults to 30 days ago; if until is zero it defaults to
// now. Results are returned chronologically (oldest first).
func (k *KeyorixCore) GetPermissionChangeAudit(ctx context.Context, since, until time.Time, limit int) (*PermissionChangeReport, error) {
	now := time.Now()

	if since.IsZero() {
		since = now.Add(-permChangeDefaultWindow)
	}
	if until.IsZero() {
		until = now
	}
	if limit <= 0 {
		limit = permChangeDefaultLimit
	}
	if limit > permChangeMaxLimit {
		limit = permChangeMaxLimit
	}

	filter := &storage.AuditFilter{
		Actions:   permChangeEventTypes,
		StartTime: &since,
		EndTime:   &until,
		Ascending: true,
		PageSize:  limit,
		Page:      1,
	}

	events, _, err := k.storage.GetAuditLogs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("permission_change_audit: query failed: %w", err)
	}

	changes := make([]PermissionChangeEvent, 0, len(events))
	for _, e := range events {
		var detail rbacAuditDetail
		if e.Diff != "" {
			// Ignore unmarshal error: we fall back to empty detail fields below.
			_ = json.Unmarshal([]byte(e.Diff), &detail)
		}

		// Resolve actor name.
		actorName := ""
		if e.UserID != nil && *e.UserID != 0 {
			if u, err := k.storage.GetUser(ctx, *e.UserID); err == nil {
				actorName = u.Username
			}
		}

		// Resolve target user name.
		targetUser := ""
		if detail.TargetUserID != 0 {
			if u, err := k.storage.GetUser(ctx, detail.TargetUserID); err == nil {
				targetUser = u.Username
			} else {
				targetUser = fmt.Sprintf("user:%d", detail.TargetUserID)
			}
		}

		// Resolve role name.
		roleName := ""
		if detail.RoleID != 0 {
			if r, err := k.storage.GetRole(ctx, detail.RoleID); err == nil {
				roleName = r.Name
			} else {
				roleName = fmt.Sprintf("role:%d", detail.RoleID)
			}
		}

		// Build scope string.
		scope := "global"
		if detail.ProjectID != 0 {
			scope = fmt.Sprintf("project:%d", detail.ProjectID)
		}

		changes = append(changes, PermissionChangeEvent{
			EventID:    e.ID,
			Action:     e.EventType,
			ActorName:  actorName,
			TargetUser: targetUser,
			RoleName:   roleName,
			Scope:      scope,
			ChangedAt:  e.EventTime,
		})
	}

	return &PermissionChangeReport{
		Since:   since,
		Until:   until,
		Changes: changes,
		Total:   len(changes),
	}, nil
}

