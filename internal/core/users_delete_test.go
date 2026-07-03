package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeleteUser_RecordsActorInAuditEvent guards #356: deleting a user must
// leave an audit trail attributing the actor who performed the deletion (via
// the threaded actorID parameter), matching the audited convention already
// used by SuspendUser/ReactivateUser/RequirePasswordReset. Exercised against a
// real store (not MockStorage) since #106 wired DeleteUser through
// guardLastAdminDeactivation, a transactional deprovision, and cache eviction —
// too many storage calls to hand-mock reliably.
func TestDeleteUser_RecordsActorInAuditEvent(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	target := seedUserWithRole(t, st, "del-target", "project_viewer", storage.Scope{ProjectID: 1})

	require.NoError(t, c.DeleteUser(ctx, admin.ID, target))

	events, _, err := st.GetAuditLogs(ctx, &storage.AuditFilter{Action: strPtr("user.deleted"), Page: 1, PageSize: 50})
	require.NoError(t, err)
	var found bool
	for _, e := range events {
		if e.UserID != nil && *e.UserID == admin.ID {
			found = true
		}
	}
	assert.True(t, found, "expected a user.deleted event attributing the acting admin")
}

// TestDeleteUser_ZeroActorOmitsAttribution confirms an unset actor (0) is not
// recorded as a spurious "user 0" attribution — the audit event's UserID is
// left nil rather than pointing at a nonexistent actor.
func TestDeleteUser_ZeroActorOmitsAttribution(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	target := seedUserWithRole(t, st, "del-target2", "project_viewer", storage.Scope{ProjectID: 1})

	require.NoError(t, c.DeleteUser(ctx, 0, target))

	events, _, err := st.GetAuditLogs(ctx, &storage.AuditFilter{Action: strPtr("user.deleted"), Page: 1, PageSize: 50})
	require.NoError(t, err)
	require.NotEmpty(t, events)
	assert.Nil(t, events[len(events)-1].UserID, "actorID 0 must not be recorded as an attributed actor")
}

func strPtr(s string) *string { return &s }
