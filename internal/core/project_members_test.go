package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectMemberLifecycle(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)

	u, err := st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice@example.com", IsActive: true})
	require.NoError(t, err)

	// No members initially.
	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, members)

	// Add as project_viewer.
	require.NoError(t, c.AddProjectMember(ctx, 0, proj, u.ID, "project_viewer"))
	members, err = c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "alice", members[0].Username)
	assert.Equal(t, "project_viewer", members[0].RoleName)

	// Adding the same role again is a conflict.
	require.Error(t, c.AddProjectMember(ctx, 0, proj, u.ID, "project_viewer"))

	// Change role to project_developer — replaces, doesn't accumulate.
	require.NoError(t, c.SetProjectMemberRole(ctx, 0, proj, u.ID, "project_developer"))
	members, err = c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1, "member should have exactly one project role after change")
	assert.Equal(t, "project_developer", members[0].RoleName)

	// Membership is project-scoped: another project sees nothing.
	other, err := c.ListProjectMembers(ctx, proj+1)
	require.NoError(t, err)
	assert.Empty(t, other)

	// Remove.
	require.NoError(t, c.RemoveProjectMember(ctx, proj, u.ID))
	members, err = c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, members)

	// Removing a non-member errors.
	require.Error(t, c.RemoveProjectMember(ctx, proj, u.ID))
}

func TestAddProjectMemberUnknownRole(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, &models.User{Username: "bob", Email: "bob@example.com", IsActive: true})
	require.NoError(t, err)
	require.Error(t, c.AddProjectMember(ctx, 0, 1, u.ID, "no_such_role"))
}
