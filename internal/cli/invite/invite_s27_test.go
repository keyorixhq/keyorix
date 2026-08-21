// invite_s27_test.go — coverage sprint 27 for internal/cli/invite.
//
// `go tool cover -func` does not attribute statements inside a closure that is
// assigned directly as a cobra.Command field literal (resendCmd's RunE is
// `RunE: func(cmd *cobra.Command, args []string) error { ... }` inside the var
// block), so it silently omits those blocks from its per-function summary even
// though the underlying coverage profile still records them as 0-count. Both
// branches below were confirmed uncovered by inspecting the raw -coverprofile
// output directly (resend.go:45-47 and resend.go:52-54), not by trusting the
// -func report.
//
// Targets:
//   - resendCmd.RunE: requireInviteAuthority fails (no roles.assign) → resend.go:45-47
//   - resendCmd.RunE: ResendInvitationLink fails (non-pending invitation) → resend.go:49-51
//   - resendCmd.RunE: full success path (prints + returns nil) → resend.go:52-54
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

// TestResendCmd_RequireAuthorityFails exercises resend.go:45-47: the actor
// resolves to a real user, but one holding only project_viewer (no
// roles.assign at the invitation's project), so requireInviteAuthority must
// reject the resend before ResendInvitationLink is ever called. Mirrors
// TestRunSend_RequireAuthorityFails/TestRunRevoke_RequireAuthorityFails
// (invite_s25_test.go / invite_s26_test.go) for the resend path.
func TestResendCmd_RequireAuthorityFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "seedInviteDB must return a valid invitation ID")

	ctx := context.Background()
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	viewerEmail := "resend_viewer_no_assign_s27@example.com"
	newUser, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "resendviewernoassigns27",
		Email:    viewerEmail,
		IsActive: true,
	})
	require.NoError(t, err)

	// The invitation seeded by seedInviteDB belongs to the "default" project,
	// which is project ID 1 (the first project created by BootstrapSystem).
	viewerRole, err := svc.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, svc.Storage().AssignRole(ctx, newUser.ID, viewerRole.ID, core.Scope{ProjectID: 1}))

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = invID
	resendBy = viewerEmail

	err = resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")

	// Confirm the invitation was NOT touched — the authority check must have
	// short-circuited before ResendInvitationLink ran.
	inv, getErr := svc.Storage().GetProjectInvitation(ctx, invID)
	require.NoError(t, getErr)
	assert.Equal(t, "pending", inv.State, "invitation must remain pending after a rejected resend attempt")
}

// TestResendCmd_ResendInvitationLinkFails exercises resend.go:52-54: the actor
// is authorized and the invitation exists, but it is no longer pending (it was
// revoked first), so the core ResendInvitationLink call itself fails and
// resendCmd.RunE must wrap that error with "failed to resend invitation link".
func TestResendCmd_ResendInvitationLinkFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	projectID, invID := seedInviteDB(t)
	require.NotZero(t, invID, "seedInviteDB must return a valid invitation ID")

	ctx := context.Background()
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	admin, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	require.NoError(t, svc.RevokeInvitation(ctx, projectID, invID, admin.ID))

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = invID
	resendBy = "admin@example.com"

	err = resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resend invitation link")
}

// TestResendCmd_SuccessPath exercises resend.go:52-54: when ResendInvitationLink
// succeeds, resendCmd.RunE must print the reissue confirmation and return nil.
// This requires credential_delivery.base_url to be configured so
// provisionSetupLinkThrottled can build the link without SMTP (out-of-band
// mode), mirroring TestRunSend_SuccessPath (invite_s25_test.go) for the resend
// path.
func TestResendCmd_SuccessPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Bootstrap the DB first using the plain default config (no base_url yet).
	_, invID := seedInviteDB(t)
	require.NotZero(t, invID, "seedInviteDB must return a valid invitation ID")

	// Write keyorix.yaml with base_url so that the next InitializeCoreService
	// call (inside resendCmd.RunE) sets setupBaseURL and enables the link build.
	writeYAML(t, baseURLYAML)

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = invID
	resendBy = "admin@example.com"

	err := resendCmd.RunE(resendCmd, nil)
	require.NoError(t, err)
}
