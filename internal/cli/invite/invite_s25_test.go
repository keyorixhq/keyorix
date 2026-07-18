// invite_s25_test.go — coverage sprint 25 for internal/cli/invite.
// Targets:
//   - runList:      service init error (encryption misconfigured) → list.go:32-34
//   - runSend:      service init error (encryption misconfigured) → send.go:42-44
//   - runSend:      resolveUserID error (--by user absent) → send.go:56-58
//   - runSend:      requireInviteAuthority fails (no roles.assign) → send.go:60-62
//   - runSend:      InviteToProjectWithLink nil inv → send.go:66-68
//   - runSend:      full success path → send.go:75-78
//   - resendCmd.RunE: service init error (encryption misconfigured) → resend.go:31-33
//   - runRevoke:    service init error (encryption misconfigured) → revoke.go:35-37
//   - runRevoke:    RevokeInvitation fails (already-revoked invitation) → revoke.go:50-52
package invite

import (
	"context"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptionYAML is a minimal keyorix.yaml with at-rest encryption enabled.
// Without KEYORIX_MASTER_PASSWORD set, InitializeCoreService returns an error.
const encryptionYAML = `storage:
  type: local
  database:
    path: ./secrets.db
  encryption:
    enabled: true
`

// baseURLYAML configures out-of-band credential delivery with a base_url so
// that provisionSetupLink succeeds without SMTP.
const baseURLYAML = `storage:
  type: local
  database:
    path: ./secrets.db
credential_delivery:
  mode: out_of_band
  base_url: http://localhost:8080
`

// writeYAML writes content to keyorix.yaml in the current working directory.
func writeYAML(t *testing.T, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(content), 0o600))
}

// ──────────────────────────── service-init failure tests ─────────────────────

// TestRunList_ServiceInitFails_Encryption exercises list.go:32-34.
func TestRunList_ServiceInitFails_Encryption(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	writeYAML(t, encryptionYAML)

	orig := listProject
	defer func() { listProject = orig }()
	listProject = "default"

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunSend_ServiceInitFails_Encryption exercises send.go:42-44.
func TestRunSend_ServiceInitFails_Encryption(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	writeYAML(t, encryptionYAML)

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "user@example.com"
	sendRole = "project_viewer"
	sendBy = "admin@example.com"
	sendProject = "default"

	err := runSend(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestResendCmd_ServiceInitFails_Encryption exercises resend.go:31-33.
func TestResendCmd_ServiceInitFails_Encryption(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	writeYAML(t, encryptionYAML)

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = 1
	resendBy = "admin@example.com"

	err := resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunRevoke_ServiceInitFails_Encryption exercises revoke.go:35-37.
func TestRunRevoke_ServiceInitFails_Encryption(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	writeYAML(t, encryptionYAML)

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	revokeID = 1
	revokeBy = "admin@example.com"

	err := runRevoke(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// ──────────────────────────── runRevoke — RevokeInvitation fails ─────────────

// TestRunRevoke_AlreadyRevoked exercises revoke.go:50-52 by calling runRevoke
// twice on the same invitation: the second call encounters an invitation that
// is no longer pending, so RevokeInvitation returns an error.
func TestRunRevoke_AlreadyRevoked(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "seedInviteDB must return a valid invitation ID")

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	revokeID = invID
	revokeBy = "admin@example.com"

	// First call must succeed.
	require.NoError(t, runRevoke(nil, nil))

	// Second call: invitation is no longer pending → failure.
	err := runRevoke(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke invitation")
}

// ──────────────────────────── runSend — mid-flow error paths ─────────────────

// TestRunSend_ByUserNotFound exercises send.go:56-58: resolveUserID fails when
// --by names a user that does not exist in the seeded DB.
func TestRunSend_ByUserNotFound(t *testing.T) {
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
	sendEmail = "guest_by_test@example.com"
	sendRole = "project_viewer"
	sendBy = "nobody_s25_unique@example.com" // does not exist
	sendProject = "default"

	err := runSend(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nobody_s25_unique@example.com")
}

// TestRunSend_RequireAuthorityFails exercises send.go:60-62: requireInviteAuthority
// returns an error when --by resolves to a user that holds only project_viewer
// (no roles.assign at the project).
func TestRunSend_RequireAuthorityFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	// Seed bootstrap DB so "default" project exists.
	_, _ = seedInviteDB(t)

	// Open the same file-backed service to create an additional viewer user.
	ctx := context.Background()
	svc, svcErr := common.InitializeCoreService()
	require.NoError(t, svcErr)

	viewerEmail := "viewer_no_assign_s25@example.com"
	newUser, createErr := svc.Storage().CreateUser(ctx, &models.User{
		Username: "viewernoassigns25",
		Email:    viewerEmail,
		IsActive: true,
	})
	require.NoError(t, createErr)

	// Assign project_viewer (which lacks roles.assign) to this user at project 1.
	viewerRole, roleErr := svc.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, roleErr)
	require.NoError(t, svc.Storage().AssignRole(ctx, newUser.ID, viewerRole.ID, core.Scope{ProjectID: 1}))

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "authority_test_guest_s25@example.com"
	sendRole = "project_viewer"
	sendBy = viewerEmail
	sendProject = "default"

	err := runSend(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// TestRunSend_InviteToProjectFails_NilInv exercises send.go:66-68: when
// InviteToProjectWithLink returns (nil, nil, err) — which happens when
// InviteToProject fails because the role is unknown — runSend must return
// "failed to send invitation".
func TestRunSend_InviteToProjectFails_NilInv(t *testing.T) {
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
	sendEmail = "guest_nil_inv_s25@example.com"
	sendRole = "totally_unknown_role_s25_9999" // no such role → InviteToProject returns nil
	sendBy = "admin@example.com"
	sendProject = "default"

	err := runSend(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send invitation")
}

// TestRunSend_SuccessPath exercises send.go:75-78: when InviteToProjectWithLink
// returns (inv, prov, nil) the function prints a success line and returns nil.
// This requires credential_delivery.base_url to be set so provisionSetupLink
// can build the link (out-of-band mode — no SMTP connection needed).
func TestRunSend_SuccessPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	// Bootstrap the DB first using the plain default config (no base_url yet).
	_, _ = seedInviteDB(t)

	// Write keyorix.yaml with base_url so that the next InitializeCoreService
	// call (inside runSend) sets setupBaseURL and enables provisionSetupLink.
	writeYAML(t, baseURLYAML)

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "success_path_s25@example.com"
	sendRole = "project_viewer"
	sendBy = "admin@example.com"
	sendProject = "default"

	err := runSend(nil, nil)
	require.NoError(t, err)
}
