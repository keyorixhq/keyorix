package invite

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunList_CrossProjectAttackerRejected is #1648's exact live-demonstrated
// exploit, as a permanent regression test: an attacker who holds a role in a
// DIFFERENT project (not merely no role at all) must not be able to list
// project "default"'s invitations by naming themselves via --by. Before the
// fix, runList performed no authorization check whatsoever, so any --by email
// that resolved to a real user succeeded regardless of that user's actual
// project membership.
func TestRunList_CrossProjectAttackerRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	// Seed bootstrap DB: creates the "default" project (id=1) and an invitation
	// on it -- this is the data the attacker must NOT be able to list.
	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "need a real invitation on the default project for this test to mean anything")

	ctx := context.Background()
	svc, svcErr := common.InitializeCoreService()
	require.NoError(t, svcErr)

	// A second, unrelated project the attacker DOES have a real role in --
	// project_admin, not a placeholder: this proves the rejection is genuinely
	// project-scoped, not just "has any role at all".
	otherProject, err := svc.CreateProject(ctx, "attacker-owned-project", "")
	require.NoError(t, err)

	attackerEmail := "cross_project_attacker@example.com"
	attacker, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "crossprojectattacker", Email: attackerEmail, IsActive: true,
	})
	require.NoError(t, err)
	adminRole, err := svc.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, svc.Storage().AssignRole(ctx, attacker.ID, adminRole.ID, core.Scope{ProjectID: otherProject.ID}))

	origProject, origStale, origBy := listProject, listStaleDays, listBy
	defer func() { listProject = origProject; listStaleDays = origStale; listBy = origBy }()
	listProject = "default"
	listStaleDays = 0
	listBy = attackerEmail

	err = runList(nil, nil)
	require.Error(t, err, "an attacker with a role in a DIFFERENT project must be refused, not shown the default project's invitations")
	assert.Contains(t, err.Error(), "roles.assign")
}

// TestRunList_LegitimateProjectAdminAllowed is the positive control for the
// test above: a user who genuinely holds roles.assign on the TARGET project
// must still be able to list its invitations -- the fix must not have turned
// this into a fully-broken command.
func TestRunList_LegitimateProjectAdminAllowed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, invID := seedInviteDB(t)
	require.NotZero(t, invID)

	ctx := context.Background()
	svc, svcErr := common.InitializeCoreService()
	require.NoError(t, svcErr)

	legitEmail := "legit_default_project_admin@example.com"
	legit, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "legitdefaultprojectadmin", Email: legitEmail, IsActive: true,
	})
	require.NoError(t, err)
	adminRole, err := svc.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	// project_id=1 is the "default" project seedInviteDB/BootstrapSystem creates.
	require.NoError(t, svc.Storage().AssignRole(ctx, legit.ID, adminRole.ID, core.Scope{ProjectID: 1}))

	origProject, origStale, origBy := listProject, listStaleDays, listBy
	defer func() { listProject = origProject; listStaleDays = origStale; listBy = origBy }()
	listProject = "default"
	listStaleDays = 0
	listBy = legitEmail

	require.NoError(t, runList(nil, nil), "a user holding roles.assign on the target project must still be able to list its invitations")
}
