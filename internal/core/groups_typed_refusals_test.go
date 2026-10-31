package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ERRSTRING-CLASS-1 item 1: the refusals core's group paths return are typed, so the
// gRPC/HTTP mappers classify them with errors.Is instead of matching words in the text.
// The refusal TEXT is unchanged (other mappers and tests still match it).

func TestGroupPaths_MalformedRequestMatchesErrInvalidGroupRequest(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()

	_, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: ""})
	require.ErrorIs(t, err, storage.ErrInvalidGroupRequest, "empty name")
	_, err = c.GetGroup(ctx, 0)
	require.ErrorIs(t, err, storage.ErrInvalidGroupRequest, "zero group id")
	_, err = c.UpdateGroup(ctx, 1, &UpdateGroupRequest{ID: 0, Name: "x"})
	require.ErrorIs(t, err, storage.ErrInvalidGroupRequest, "update zero id")
	require.ErrorIs(t, c.DeleteGroup(ctx, 1, 0), storage.ErrInvalidGroupRequest, "delete zero id")
	_, err = c.RestoreGroup(ctx, 1, 0)
	require.ErrorIs(t, err, storage.ErrInvalidGroupRequest, "restore zero id")
	require.ErrorIs(t, c.AddUserToGroup(ctx, 1, false, 0, 0, 0), storage.ErrInvalidGroupRequest, "add zero ids")
	require.ErrorIs(t, c.RemoveUserFromGroup(ctx, 1, 0, 0, 0), storage.ErrInvalidGroupRequest, "remove zero ids")
	_, err = c.GetGroupMembers(ctx, 0)
	require.ErrorIs(t, err, storage.ErrInvalidGroupRequest, "members zero id")

	// A real lookup failure is NOT a malformed request.
	_, err = c.GetGroup(ctx, 987654)
	require.Error(t, err)
	assert.NotErrorIs(t, err, storage.ErrInvalidGroupRequest)
}

func TestAddUserToGroup_CeilingRefusalMatchesErrPermissionDenied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "group-granter-typed", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "group-target-typed", Email: "group-target-typed@example.com", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	grp, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "ceiling-typed-group"})
	require.NoError(t, err)
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, viewerRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignRoleToGroupWithExpiry(ctx, grp.ID, adminRole.ID, storage.Scope{ProjectID: 1}, time.Now().Add(time.Hour)))

	err = c.AddUserToGroup(WithSelfMachineGranter(ctx, granter.ID), 0, true, target.ID, grp.ID, 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPermissionDenied, "the roles.assign ceiling refusal is a typed authorization refusal")
	assert.Contains(t, err.Error(), "cannot grant this role", "refusal text is unchanged")
}
