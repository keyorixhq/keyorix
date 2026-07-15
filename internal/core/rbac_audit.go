// rbac_audit.go — read side of the RBAC audit trail.
//
// Role assignments/removals are written to the shared audit_events table (see
// audit.go LogRoleAssigned/LogRoleRemoved), with the target/role/scope carried in
// the event's structured Diff. ListRBACAuditLogs pulls those event types back out
// and reconstructs the per-change attribution.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// RBACAuditEntry is a reconstructed RBAC audit record: who changed which role for
// whom, at what scope, and when.
type RBACAuditEntry struct {
	ID           uint
	Action       string // role.assigned | role.removed | role.group_assigned | role.group_removed | group.member_added | group.member_removed
	ActorUserID  *uint  // the principal who made the change (nil for system/CLI)
	TargetUserID *uint  // set for user-role events
	GroupID      *uint  // set for group-role events
	RoleID       *uint
	PermissionID *uint // set for permission-to-role events
	ProjectID    *uint
	Details      string
	CreatedAt    time.Time
}

// ListRBACAuditLogs returns the RBAC audit trail (role assignments/removals),
// most-recent first, with pagination.
func (c *KeyorixCore) ListRBACAuditLogs(ctx context.Context, page, pageSize int) ([]*RBACAuditEntry, int64, error) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		Actions:  rbacAuditEventTypes,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", "failed to read RBAC audit logs", err)
	}

	entries := make([]*RBACAuditEntry, 0, len(events))
	for _, e := range events {
		entry := &RBACAuditEntry{
			ID:          e.ID,
			Action:      e.EventType,
			ActorUserID: e.UserID,
			Details:     e.Description,
			CreatedAt:   e.EventTime,
		}
		// Reconstruct target/role/scope from the structured diff.
		var d rbacAuditDetail
		if e.Diff != "" && json.Unmarshal([]byte(e.Diff), &d) == nil {
			if d.TargetUserID != 0 {
				t := d.TargetUserID
				entry.TargetUserID = &t
			}
			if d.GroupID != 0 {
				g := d.GroupID
				entry.GroupID = &g
			}
			if d.RoleID != 0 {
				r := d.RoleID
				entry.RoleID = &r
			}
			if d.PermissionID != 0 {
				pid := d.PermissionID
				entry.PermissionID = &pid
			}
			if d.ProjectID != 0 {
				p := d.ProjectID
				entry.ProjectID = &p
			}
		}
		entries = append(entries, entry)
	}
	return entries, total, nil
}
