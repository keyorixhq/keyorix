// invite_s26_test.go — coverage sprint 26 for internal/cli/invite.
// Targets the two remaining uncovered branches after sprint 25:
//   - runRevoke: requireInviteAuthority fails (no roles.assign) → revoke.go:50-52
//   - runList:   ListProjectInvitations/StaleInvitations fails → list.go:52-54
package invite

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ──────────────────────────── runRevoke — authority failure ──────────────────

// TestRunRevoke_RequireAuthorityFails exercises revoke.go:50-52: when
// requireInviteAuthority rejects the --by actor (resolves to a real user, but
// one holding only project_viewer — no roles.assign at the invitation's
// project), runRevoke must propagate that error and must NOT proceed to call
// RevokeInvitation. Mirrors TestRunSend_RequireAuthorityFails (invite_s25_test.go)
// for the revoke path.
func TestRunRevoke_RequireAuthorityFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "seedInviteDB must return a valid invitation ID")

	ctx := context.Background()
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	viewerEmail := "revoke_viewer_no_assign_s26@example.com"
	newUser, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "revokeviewernoassigns26",
		Email:    viewerEmail,
		IsActive: true,
	})
	require.NoError(t, err)

	// The invitation seeded by seedInviteDB belongs to the "default" project,
	// which is project ID 1 (the first project created by BootstrapSystem).
	viewerRole, err := svc.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, svc.Storage().AssignRole(ctx, newUser.ID, viewerRole.ID, core.Scope{ProjectID: 1}))

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	revokeID = invID
	revokeBy = viewerEmail

	revokeErr := runRevoke(nil, nil)
	require.Error(t, revokeErr)
	assert.Contains(t, revokeErr.Error(), "roles.assign")

	// Confirm the invitation was NOT revoked — the authority check must have
	// short-circuited before RevokeInvitation ran.
	inv, getErr := svc.Storage().GetProjectInvitation(ctx, invID)
	require.NoError(t, getErr)
	assert.Equal(t, "pending", inv.State, "invitation must remain pending after a rejected revoke attempt")
}

// ──────────────────────────── runList — list query failure ───────────────────

// TestRunList_ListInvitationsFails exercises list.go:52-54: when the storage
// query underlying ListProjectInvitations fails, runList must wrap and return
// that error rather than panicking or silently reporting an empty list.
//
// The project_invitations table itself is left in place (dropping it outright
// would just have factory.go's migrateDatabase recreate it as empty on the next
// InitializeCoreService call inside runList, since it only re-creates tables
// that are MISSING — see the `if !invitationsExists` branch). GORM's Find
// issues a bare `SELECT *`, so dropping a column that is merely part of the
// model (e.g. email) does not break the query. ListProjectInvitations'
// `Where("project_id = ?", projectID)` clause, however, references project_id
// directly in the generated SQL, so dropping THAT column guarantees the
// underlying SELECT genuinely fails with "no such column: project_id".
func TestRunList_ListInvitationsFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "need a seeded invitation so the table pre-exists before corrupting it")

	db, err := gorm.Open(sqlite.Open("./secrets.db"), &gorm.Config{})
	require.NoError(t, err)
	// The project_id column carries a GORM-generated index
	// (idx_project_invitations_project_id); SQLite refuses to drop a column
	// that an index still references, so the index must go first.
	require.NoError(t, db.Exec("DROP INDEX IF EXISTS idx_project_invitations_project_id").Error)
	require.NoError(t, db.Exec("ALTER TABLE project_invitations DROP COLUMN project_id").Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	origProject, origStale := listProject, listStaleDays
	defer func() { listProject = origProject; listStaleDays = origStale }()
	listProject = ""
	listStaleDays = 0

	err = runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list invitations")
}

// TestRunList_StaleInvitationsFails is the --stale-days sibling of
// TestRunList_ListInvitationsFails: StaleInvitations calls the same broken
// storage query internally.
func TestRunList_StaleInvitationsFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "need a seeded invitation so the table pre-exists before corrupting it")

	db, err := gorm.Open(sqlite.Open("./secrets.db"), &gorm.Config{})
	require.NoError(t, err)
	// See TestRunList_ListInvitationsFails: the index on project_id must be
	// dropped before the column itself can be.
	require.NoError(t, db.Exec("DROP INDEX IF EXISTS idx_project_invitations_project_id").Error)
	require.NoError(t, db.Exec("ALTER TABLE project_invitations DROP COLUMN project_id").Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	origProject, origStale := listProject, listStaleDays
	defer func() { listProject = origProject; listStaleDays = origStale }()
	listProject = ""
	listStaleDays = 7

	err = runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list invitations")
}
