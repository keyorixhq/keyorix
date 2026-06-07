package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRBACAuditCore(t *testing.T) *KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.UserRole{}))
	return NewKeyorixCore(store.NewLocalStorage(db))
}

func TestRBACAuditTrail_AssignAndRemove(t *testing.T) {
	c := newRBACAuditCore(t)
	ctx := context.Background()

	require.NoError(t, c.AssignUserRole(ctx, 5, 10, 2, Scope{ProjectID: 3}))
	require.NoError(t, c.RemoveUserRole(ctx, 5, 10, 2, Scope{ProjectID: 3}))

	entries, total, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(2))

	var assigned, removed *RBACAuditEntry
	for _, e := range entries {
		switch e.Action {
		case EventRoleAssigned:
			assigned = e
		case EventRoleRemoved:
			removed = e
		}
	}

	require.NotNil(t, assigned, "expected a role.assigned entry")
	require.NotNil(t, assigned.ActorUserID)
	assert.Equal(t, uint(5), *assigned.ActorUserID)
	require.NotNil(t, assigned.TargetUserID)
	assert.Equal(t, uint(10), *assigned.TargetUserID)
	require.NotNil(t, assigned.RoleID)
	assert.Equal(t, uint(2), *assigned.RoleID)
	require.NotNil(t, assigned.ProjectID)
	assert.Equal(t, uint(3), *assigned.ProjectID)

	require.NotNil(t, removed, "expected a role.removed entry")
	require.NotNil(t, removed.TargetUserID)
	assert.Equal(t, uint(10), *removed.TargetUserID)
}

// A change made without an authenticated principal (actorID 0, e.g. local CLI)
// records no actor.
func TestRBACAuditTrail_SystemActor(t *testing.T) {
	c := newRBACAuditCore(t)
	ctx := context.Background()

	require.NoError(t, c.AssignUserRole(ctx, 0, 11, 4, Scope{}))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].ActorUserID, "system/CLI actor should be unset")
	require.NotNil(t, entries[0].RoleID)
	assert.Equal(t, uint(4), *entries[0].RoleID)
}

// SetUserRoles diffs the current vs desired set and audits each resulting change.
func TestRBACAuditTrail_SetUserRolesEmitsPerChange(t *testing.T) {
	c := newRBACAuditCore(t)
	ctx := context.Background()

	// From {} to {1,2}: two assignments.
	require.NoError(t, c.SetUserRoles(ctx, 9, 20, []uint{1, 2}, Scope{}))
	// From {1,2} to {2,3}: remove 1, add 3.
	require.NoError(t, c.SetUserRoles(ctx, 9, 20, []uint{2, 3}, Scope{}))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)

	var assigns, removes int
	for _, e := range entries {
		switch e.Action {
		case EventRoleAssigned:
			assigns++
		case EventRoleRemoved:
			removes++
		}
		require.NotNil(t, e.ActorUserID)
		assert.Equal(t, uint(9), *e.ActorUserID)
	}
	assert.Equal(t, 3, assigns, "assigned roles 1,2 then 3")
	assert.Equal(t, 1, removes, "removed role 1")
}
