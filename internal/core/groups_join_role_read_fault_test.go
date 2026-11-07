package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3988: validateGroupJoinRoles skipped a group role on ANY GetRole error, so a
// transient storage fault on the role read skipped that role's grant ceiling and
// AddUserToGroup let a project_viewer join a group that confers admin. A failed
// read must refuse the join with the retryable storage-unavailable error.
func TestAddUserToGroup_GetRoleFaultRefusesJoin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	attacker := seedUserWithRole(t, st, "grf-attacker", "project_viewer", storage.Scope{ProjectID: 1})

	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "grf-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{}))

	fs := faultstorage.NewFaultyStorage(st, nil)
	fc := NewKeyorixCore(fs)
	fs.Arm(&faultstorage.FaultSpec{Method: "GetRole", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected GetRole fault: connection reset")})

	err = fc.AddUserToGroup(ctx, attacker, false, attacker, group.ID, 0)
	require.NotEmpty(t, fs.Fired(), "the GetRole fault must have fired")
	require.Error(t, err, "a GetRole fault must not skip the grant ceiling")
	assert.True(t, IsStorageReadUnavailable(err), "want the retryable storage-unavailable error, got %v", err)

	members, err := c.GetGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	assert.Empty(t, members, "the join must not have happened")
}

// The counterpart: a role that is positively gone still confers nothing and is
// still skipped, so the join of a group whose only grant is a deleted role works.
func TestAddUserToGroup_DeletedGroupRoleStillSkipped(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "grf-actor", "project_viewer", storage.Scope{ProjectID: 1})

	gone := &models.Role{Name: "grf-gone", NameFolded: "grf-gone"}
	require.NoError(t, st.DB().Create(gone).Error)
	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "grf-orphans"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, gone.ID, storage.Scope{}))
	require.NoError(t, st.DB().Exec("DELETE FROM roles WHERE id = ?", gone.ID).Error)

	grants, err := st.ListGroupRoleAssignments(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1, "the dangling grant must still be listed, or the not-found branch is not exercised")
	_, err = st.GetRole(ctx, gone.ID)
	require.True(t, isPositiveNotFound(err), "premise: the role read is a positive not-found, got %v", err)

	require.NoError(t, c.AddUserToGroup(ctx, actor, false, actor, group.ID, 0))
}

// Sibling: requireGroupJoinNoSoDViolationOn dropped a role whose read failed from
// the permission set it checks, so a toxic pair could complete on a fault.
func TestRequireGroupJoinNoSoDViolation_GetRoleFaultFailsClosed(t *testing.T) {
	t.Parallel()
	_, st := newBootstrappedCore(t)
	ctx := context.Background()
	user := seedUserWithRole(t, st, "grf-sod", "project_viewer", storage.Scope{ProjectID: 1})
	require.NoError(t, st.DB().Create(&models.SoDPolicy{Name: "grf-pol", PermissionA: "secrets.read", PermissionB: "secrets.write"}).Error)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)

	fs := faultstorage.NewFaultyStorage(st, nil)
	fs.Arm(&faultstorage.FaultSpec{Method: "GetRole", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected GetRole fault: timeout")})
	err = requireGroupJoinNoSoDViolationOn(ctx, fs, user, []storage.RoleAssignment{{RoleID: viewer.ID}})
	require.NotEmpty(t, fs.Fired(), "the GetRole fault must have fired")
	require.Error(t, err)
	assert.True(t, IsStorageReadUnavailable(err), "want the retryable storage-unavailable error, got %v", err)
}

// Sibling: requireInvitationGrantScopesValid treated a failed role read as an
// unknown role and passed the invitation on to be granted unchecked.
func TestRequireInvitationGrantScopesValid_GetRoleByNameFaultFailsClosed(t *testing.T) {
	t.Parallel()
	_, st := newBootstrappedCore(t)
	ctx := context.Background()

	fs := faultstorage.NewFaultyStorage(st, nil)
	fc := NewKeyorixCore(fs)
	fs.Arm(&faultstorage.FaultSpec{Method: "GetRoleByName", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected GetRoleByName fault: timeout")})
	err := fc.requireInvitationGrantScopesValid(ctx, &models.ProjectInvitation{ProjectID: 1, Role: "project_viewer"})
	require.NotEmpty(t, fs.Fired(), "the GetRoleByName fault must have fired")
	require.Error(t, err)
	assert.True(t, IsStorageReadUnavailable(err), "want the retryable storage-unavailable error, got %v", err)
}
