package core

// #2955: the docs promise break-glass activations alert the admins, but the
// fan-out read ListProjectMembers, which matches user_roles.project_id exactly.
// An install-wide (global-scope) admin -- the usual admin on a fresh install --
// holds no project-scoped row, so they were never considered and got 0
// notifications. These assert the EFFECT (a persisted notification row for the
// global admin), not the return value: notifyBreakGlassAdmins' notify() is
// best-effort, so ActivateBreakGlass succeeds either way.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedBreakGlassActor returns a project plus a project-viewer actor ready to
// activate break-glass with the "editor" emergency role.
func seedBreakGlassActor(t *testing.T, c *KeyorixCore, st *store.LocalStorage) (projectID, actorID uint) {
	t.Helper()
	ctx := context.Background()
	proj, err := st.CreateProject(ctx, &models.Project{Name: "bg-global-notify"})
	require.NoError(t, err)
	actor, err := st.CreateUser(ctx, foldedTestUser(t, "bg-g-actor", "bg-g-actor@example.com"))
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, actor.ID, viewer.ID, storage.Scope{ProjectID: proj.ID}))
	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "editor", DefaultTTL: time.Hour, MaxTTL: time.Hour})
	return proj.ID, actor.ID
}

func TestActivateBreakGlass_NotifiesGlobalAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	projectID, actorID := seedBreakGlassActor(t, c, st)

	globalAdmin, err := st.CreateUser(ctx, foldedTestUser(t, "bg-global-admin", "bg-global-admin@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, globalAdmin.ID, adminRole.ID, storage.Scope{}))

	_, err = c.ActivateBreakGlass(ctx, projectID, actorID, "prod incident #2955", "")
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, globalAdmin.ID, false, 10)
	require.NoError(t, err)
	require.Len(t, notes, 1, "an install-wide admin must be alerted of a break-glass activation (#2955)")
	assert.Equal(t, EventBreakGlassActivated, notes[0].Type)
	require.NotNil(t, notes[0].ProjectID)
	assert.Equal(t, projectID, *notes[0].ProjectID)
}

func TestActivateBreakGlass_NotifiesGroupInheritedGlobalAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	projectID, actorID := seedBreakGlassActor(t, c, st)

	member, err := st.CreateUser(ctx, foldedTestUser(t, "bg-group-admin", "bg-group-admin@example.com"))
	require.NoError(t, err)
	grp, err := st.CreateGroup(ctx, &models.Group{Name: "bg-global-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AddUserToGroup(ctx, member.ID, grp.ID, 0))
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, grp.ID, adminRole.ID, storage.Scope{}))

	_, err = c.ActivateBreakGlass(ctx, projectID, actorID, "prod incident #2955", "")
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, member.ID, false, 10)
	require.NoError(t, err)
	require.Len(t, notes, 1, "a group-inherited install-wide admin must be alerted too (#2955)")
}

// A user who is BOTH a project admin and a global admin gets one alert, not two.
func TestActivateBreakGlass_DedupesAdminWithBothScopes(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	projectID, actorID := seedBreakGlassActor(t, c, st)

	both, err := st.CreateUser(ctx, foldedTestUser(t, "bg-both-admin", "bg-both-admin@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, both.ID, adminRole.ID, storage.Scope{}))
	makeProjectApprover(t, st, both.ID, projectID, "project_admin")

	_, err = c.ActivateBreakGlass(ctx, projectID, actorID, "prod incident #2955", "")
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, both.ID, false, 10)
	require.NoError(t, err)
	assert.Len(t, notes, 1, "one alert per recipient, however many scopes grant admin")
}

// Audit must be written regardless of who is notified.
func TestActivateBreakGlass_StillAuditedWithGlobalAdminAlert(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	projectID, actorID := seedBreakGlassActor(t, c, st)

	_, err := c.ActivateBreakGlass(ctx, projectID, actorID, "prod incident #2955", "")
	require.NoError(t, err)

	action := EventBreakGlassActivated
	events, _, err := st.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action})
	require.NoError(t, err)
	assert.NotEmpty(t, events, "break_glass.activated audit event must still be written")
}
