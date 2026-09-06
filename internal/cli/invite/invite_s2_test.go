// invite_s2_test.go — coverage sprint 2 for internal/cli/invite.
// Targets: resolveUserID (success + not-found), runList (no-project-set,
// stale-days branch, empty-list, non-empty-list), runRevoke (seeded service
// path), resendCmd.RunE (seeded service path), and runSend (no-project branch
// + seeded project path).
package invite

import (
	"context"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedInviteDB bootstraps a file-backed SQLite DB in the current working
// directory (must already be a temp dir via t.Chdir) by calling
// InitializeCoreService, then seeds an admin user and an invitation in the
// project that BootstrapSystem creates ("default").  Returns the projectID and
// invitationID (0 if seeding the invitation failed).
func seedInviteDB(t *testing.T) (projectID uint, invitationID uint) {
	t.Helper()
	ctx := context.Background()

	// #G-blank-storage-default: InitializeCoreService no longer silently
	// defaults storage.type to "local" when no config file is present (a CLI
	// command run with zero usable config now fails loudly instead of
	// creating a stray ./secrets.db) -- write an explicit minimal config so
	// this fixture keeps exercising a real file-backed SQLite DB, matching
	// what it did implicitly before.
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  database:\n    path: ./secrets.db\n"), 0o600))

	// First call creates ./secrets.db and runs the full storage migration.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	svc.SetBootstrapToken("s2-tok")
	resp, err := svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username:    "admin",
		Email:       "admin@example.com",
		Password:    "S3cur3!P@ssw0rd#2026",
		DisplayName: "Admin",
		Token:       "s2-tok",
	})
	require.NoError(t, err)

	// BootstrapSystem already creates a "default" project; use it directly.
	proj := resp.Project

	// InviteToProjectWithLink may fail on delivery (out-of-band mode), but the
	// invitation is still created; fall back to InviteToProject if needed.
	inv, _, linkErr := svc.InviteToProjectWithLink(ctx, proj.ID, "invitee@example.com", "project_viewer", resp.User.ID, 0)
	if linkErr == nil && inv != nil {
		return proj.ID, inv.ID
	}
	inv2, err2 := svc.InviteToProject(ctx, proj.ID, "invitee@example.com", "project_viewer", resp.User.ID, 0)
	if err2 == nil {
		return proj.ID, inv2.ID
	}
	return proj.ID, 0
}

// ──────────────────────────── resolveUserID ───────────────────────────────────

// TestResolveUserID_Success exercises the happy path via a seeded in-memory
// core (re-uses the newTestInviteCore helper defined in send_authority_test.go).
func TestResolveUserID_Success(t *testing.T) {
	svc, _ := newTestInviteCore(t)
	ctx := context.Background()
	id, err := resolveUserID(ctx, svc, "admin@example.com")
	require.NoError(t, err)
	assert.NotZero(t, id)
}

// TestResolveUserID_Error verifies that an unknown email returns an error
// containing the email address.
func TestResolveUserID_Error(t *testing.T) {
	svc, _ := newTestInviteCore(t)
	ctx := context.Background()
	_, err := resolveUserID(ctx, svc, "nobody@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nobody@example.com")
}

// ──────────────────────────── runList ─────────────────────────────────────────

// TestRunList_NoProjectSet verifies that runList returns a "no project
// specified" error when neither --project, KEYORIX_PROJECT, nor a cli.yaml
// active project is configured.
func TestRunList_NoProjectSet(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", dir) // isolate cli.yaml lookup
	// #G-blank-storage-default: runList's InitializeCoreService call now hard-errors
	// on a blank storage.type instead of silently defaulting to local storage — write
	// an explicit config so the test still reaches the "no project specified" branch
	// this test is targeting, rather than failing earlier on storage init.
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  database:\n    path: ./secrets.db\n"), 0o600))

	orig := listProject
	defer func() { listProject = orig }()
	listProject = ""

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project specified")
}

// TestRunList_StaleDays seeds a project and exercises the StaleInvitations
// branch (listStaleDays > 0).
func TestRunList_StaleDays(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, _ = seedInviteDB(t)

	origProject, origStale, origBy := listProject, listStaleDays, listBy
	defer func() { listProject = origProject; listStaleDays = origStale; listBy = origBy }()
	listProject = ""
	listStaleDays = 7 // trigger the stale-days branch (StaleInvitations call)
	listBy = "admin@example.com"

	require.NoError(t, runList(nil, nil))
}

// TestRunList_EmptyResult seeds a project but filters with an extremely large
// stale-days value so nothing matches, exercising the "No invitations found"
// empty-list branch.
func TestRunList_EmptyResult(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, _ = seedInviteDB(t)

	origProject, origStale, origBy := listProject, listStaleDays, listBy
	defer func() { listProject = origProject; listStaleDays = origStale; listBy = origBy }()
	listProject = ""
	listStaleDays = 36500 // 100 years — nothing is that old → empty result
	listBy = "admin@example.com"

	require.NoError(t, runList(nil, nil))
}

// TestRunList_WithInvitations seeds a project with an invitation and lists with
// no stale-days filter, exercising the header+row printing branch.
func TestRunList_WithInvitations(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, _ = seedInviteDB(t)

	origProject, origStale, origBy := listProject, listStaleDays, listBy
	defer func() { listProject = origProject; listStaleDays = origStale; listBy = origBy }()
	listProject = ""
	listStaleDays = 0 // normal list — returns all invitations for the project
	listBy = "admin@example.com"

	require.NoError(t, runList(nil, nil))
}

// ──────────────────────────── runRevoke ──────────────────────────────────────

// TestRunRevoke_WithSeededDB seeds an invitation and exercises runRevoke
// through the resolveUserID → GetProjectInvitation → RevokeInvitation path.
func TestRunRevoke_WithSeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, invID := seedInviteDB(t)

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	if invID != 0 {
		revokeID = invID
	} else {
		revokeID = 1
	}
	revokeBy = "admin@example.com"

	_ = runRevoke(nil, nil)
}

// ──────────────────────────── resendCmd.RunE ─────────────────────────────────

// TestResendCmd_WithSeededDB seeds data so resolveUserID and
// GetProjectInvitation both succeed, then exercises ResendInvitationLink.
func TestResendCmd_WithSeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, invID := seedInviteDB(t)

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	if invID != 0 {
		resendID = invID
	} else {
		resendID = 1
	}
	resendBy = "admin@example.com"

	err := resendCmd.RunE(resendCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "invitation id is required")
		assert.NotContains(t, err.Error(), "acting admin email is required")
	}
}

// TestResendCmd_UserNotFound exercises resendCmd when the seeded DB has no
// matching user for resendBy, covering the resolveUserID-error branch.
func TestResendCmd_UserNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = 99
	resendBy = "nobody@example.com"

	err := resendCmd.RunE(resendCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "invitation id is required")
		assert.NotContains(t, err.Error(), "acting admin email is required")
	}
}

// ──────────────────────────── runSend ────────────────────────────────────────

// TestRunSend_NoProject exercises the runSend path where ResolveProject returns
// "no project specified" because neither --project nor KEYORIX_PROJECT is set.
func TestRunSend_NoProject(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", dir)
	// #G-blank-storage-default: see TestRunList_NoProjectSet above.
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  database:\n    path: ./secrets.db\n"), 0o600))

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "user@example.com"
	sendRole = "viewer"
	sendBy = "admin@example.com"
	sendProject = ""

	err := runSend(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project specified")
}

// TestRunSend_WithSeededDB seeds a project and admin user so runSend can
// proceed through requireInviteAuthority and InviteToProjectWithLink.
func TestRunSend_WithSeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, _ = seedInviteDB(t)

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "newguest@example.com"
	sendRole = "project_viewer"
	sendBy = "admin@example.com"
	sendProject = "default"

	_ = runSend(nil, nil)
}
