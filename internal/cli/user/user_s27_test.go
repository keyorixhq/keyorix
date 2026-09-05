// user_s27_test.go — coverage sprint 27 for internal/cli/user.
// Targets the remaining gaps left by sprint 26 (measured via go tool cover -func
// with XDG_CONFIG_HOME isolated from any local ~/.keyorix/cli.yaml):
//   - requireUserAuthority: the Authorize() storage-error branch (not just the
//     "unauthorized" boolean branch already covered by by_authority_test.go)
//   - suspendCmd / reactivateCmd: their own embedded RunE apply closures had
//     never actually been invoked (existing tests exercised equivalent
//     closures written directly in the test file, not these specific ones)
//   - revokeSessionsCmd: InitializeCoreService failure, requireUserAuthority
//     rejection, and RevokeUserSessions failure branches
//   - runLifecycle: the InitializeCoreService failure branch
//   - runCreate: requireUserAuthority rejection on both the --setup-link and
//     --one-time-password createBy paths
//   - runDelete / runGet / runUpdate: InitializeCoreService failure branches,
//     plus DeleteUser failure for a nonexistent target
//   - resendSetupLinkCmd: InitializeCoreService failure, requireUserAuthority
//     rejection, and the full success path (fmt.Printf + PrintProvisionResult)
package user

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
)

// setupInitFailureConfig writes a keyorix.yaml that enables storage encryption
// without a master password available, so common.InitializeCoreService fails
// deterministically — mirroring TestSuspendInactiveCmd_LocalInitError's
// established pattern. Returns nothing; sets env vars for the duration of the
// test via t.Setenv (auto-restored).
func setupInitFailureConfig(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	cfgContent := "storage:\n  encryption:\n    enabled: true\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
}

// createUnprivilegedUser creates a plain user (no role assigned) against the
// service backing the current working directory's file DB, for use as an
// unprivileged --by actor. Mirrors the pattern in by_authority_test.go's
// TestRunLifecycle_UnprivilegedByRejected / TestRunDelete_UnprivilegedByRejected.
func createUnprivilegedUser(t *testing.T, username, email string) {
	t.Helper()
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()
	_, err = svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: email,
		DisplayName: username, Password: "Unpr1v!P@ssw0rd#2026",
	})
	require.NoError(t, err)
}

// ──────────────────────── requireUserAuthority: Authorize() storage error ────

// TestRequireUserAuthority_AuthorizeStorageError covers the "failed to verify
// --by authority" branch (distinct from the "does not hold <perm>" branch
// already covered): Authorize itself must return an error, not just false.
// Closing the underlying DB connection forces scopedRoleIDs to fail.
func TestRequireUserAuthority_AuthorizeStorageError(t *testing.T) {
	svc, st := newUserTestCore(t)
	ctx := context.Background()
	admin, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	sqlDB, err := st.DB().DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	err = requireUserAuthority(ctx, svc, admin.ID, permUsersWrite)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// ──────────────────────── suspendCmd / reactivateCmd: own RunE closures ──────

// TestSuspendCmd_RunE_SeededDB_InvokesOwnClosure exercises suspendCmd's own
// embedded RunE (and the apply closure literal inside it) end to end against a
// seeded DB, rather than a structurally-similar closure written directly in a
// test. This is the only way to cover that specific closure's body.
func TestSuspendCmd_RunE_SeededDB_InvokesOwnClosure(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origBy := suspendUserID, suspendBy
	defer func() { suspendUserID = origID; suspendBy = origBy }()
	suspendUserID = targetID
	suspendBy = "admin@example.com"

	require.NoError(t, suspendCmd.RunE(suspendCmd, nil))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	u, err := svc.GetUser(context.Background(), targetID)
	require.NoError(t, err)
	assert.Equal(t, core.AccountSuspended, u.AccountState, "target must actually be suspended by suspendCmd's own closure")
}

// TestReactivateCmd_RunE_SeededDB_InvokesOwnClosure is the reactivate sibling:
// suspend first (via runLifecycle, already covered), then reactivate through
// reactivateCmd's own embedded RunE/apply closure.
func TestReactivateCmd_RunE_SeededDB_InvokesOwnClosure(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	suspendErr := runLifecycle(targetID, "admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	require.NoError(t, suspendErr)

	origID, origBy := reactivateUserID, reactivateBy
	defer func() { reactivateUserID = origID; reactivateBy = origBy }()
	reactivateUserID = targetID
	reactivateBy = "admin@example.com"

	require.NoError(t, reactivateCmd.RunE(reactivateCmd, nil))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	u, err := svc.GetUser(context.Background(), targetID)
	require.NoError(t, err)
	assert.Equal(t, core.AccountActive, u.AccountState, "target must actually be reactivated by reactivateCmd's own closure")
}

// ──────────────────────── revokeSessionsCmd: remaining branches ──────────────

// TestRevokeSessionsCmd_RunE_ServiceInitFailure covers the InitializeCoreService
// error branch inside revokeSessionsCmd's RunE.
func TestRevokeSessionsCmd_RunE_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID = 1
	revokeSessionsBy = "admin@example.com"

	err := revokeSessionsCmd.RunE(revokeSessionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRevokeSessionsCmd_RunE_UnprivilegedByRejected covers the
// requireUserAuthority rejection branch inside revokeSessionsCmd's RunE.
func TestRevokeSessionsCmd_RunE_UnprivilegedByRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)
	createUnprivilegedUser(t, "revoke-victim", "revoke-victim@example.com")

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID = targetID
	revokeSessionsBy = "revoke-victim@example.com"

	err := revokeSessionsCmd.RunE(revokeSessionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
	assert.Contains(t, err.Error(), "refusing to attribute")
}

// TestRevokeSessionsCmd_RunE_RevokeSessionsError covers the
// service.RevokeUserSessions failure branch (target user does not exist).
func TestRevokeSessionsCmd_RunE_RevokeSessionsError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID = 99999
	revokeSessionsBy = "admin@example.com"

	err := revokeSessionsCmd.RunE(revokeSessionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed:")
}

// ──────────────────────── runLifecycle: service init failure ─────────────────

// TestRunLifecycle_ServiceInitFailure covers the InitializeCoreService failure
// branch inside runLifecycle (distinct from the resolveAdminID / requireUserAuthority
// / apply error branches already covered).
func TestRunLifecycle_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	err := runLifecycle(1, "admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// ──────────────────────── runCreate: requireUserAuthority rejection ──────────

// TestRunCreate_SetupLink_UnprivilegedByRejected covers the requireUserAuthority
// rejection branch on the --setup-link createBy path (distinct from the
// resolveAdminID "unknown email" branch already covered).
func TestRunCreate_SetupLink_UnprivilegedByRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)
	createUnprivilegedUser(t, "sl-victim", "sl-victim@example.com")

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
		createBy = origBy
	}()
	createUsername = "slrejected"
	createEmail = "slrejected@example.com"
	createSetupLink = true
	createOneTimePassword = false
	createPassword = ""
	createBy = "sl-victim@example.com"

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
	assert.Contains(t, err.Error(), "refusing to attribute")
}

// TestRunCreate_OTP_UnprivilegedByRejected is the one-time-password sibling.
func TestRunCreate_OTP_UnprivilegedByRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)
	createUnprivilegedUser(t, "otp-victim", "otp-victim@example.com")

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
		createBy = origBy
	}()
	createUsername = "otprejected"
	createEmail = "otprejected@example.com"
	createSetupLink = false
	createOneTimePassword = true
	createPassword = ""
	createBy = "otp-victim@example.com"

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
	assert.Contains(t, err.Error(), "refusing to attribute")
}

// ──────────────────────── runDelete / runGet / runUpdate: init failure ───────

func TestRunDelete_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID = 1
	deleteBy = "admin@example.com"
	deleteForce = true

	err := runDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunGet_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	origID, origEmail := getUserID, getUserEmail
	defer func() { getUserID = origID; getUserEmail = origEmail }()
	getUserID = 1
	getUserEmail = ""

	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunUpdate_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	origID, origU := updateUserID, updateUsername
	defer func() { updateUserID = origID; updateUsername = origU }()
	updateUserID = 1
	updateUsername = "whatever"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunList_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	origPage, origSize := listPage, listPageSize
	defer func() { listPage = origPage; listPageSize = origSize }()
	listPage = 1
	listPageSize = 20

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunDelete_DeleteUserError_NonexistentTarget covers the service.DeleteUser
// failure branch: a valid, authorized admin deleting a user ID that does not
// exist.
func TestRunDelete_DeleteUserError_NonexistentTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID = 99999
	deleteBy = "admin@example.com"
	deleteForce = true

	err := runDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete user")
}

// ──────────────────────── resendSetupLinkCmd: remaining branches ─────────────

func TestResendSetupLinkCmd_RunE_ServiceInitFailure(t *testing.T) {
	setupInitFailureConfig(t)

	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID = 1
	resendSetupLinkBy = "admin@example.com"

	err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestResendSetupLinkCmd_RunE_UnprivilegedByRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)
	createUnprivilegedUser(t, "resend-victim", "resend-victim@example.com")

	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID = targetID
	resendSetupLinkBy = "resend-victim@example.com"

	err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
	assert.Contains(t, err.Error(), "refusing to attribute")
}

// TestResendSetupLinkCmd_RunE_Success_WithBaseURL covers the full success path
// (fmt.Printf + common.PrintProvisionResult + return nil): with a configured
// credential_delivery.base_url, ResendAccountSetupLink can mint an out-of-band
// link instead of failing on ErrSetupBaseURLRequired.
func TestResendSetupLinkCmd_RunE_Success_WithBaseURL(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// #G-blank-storage-default: storage.type must be explicit here too -- see
	// seedUserDB's own doc comment in user_s2_test.go for why it no longer
	// overwrites a pre-existing keyorix.yaml.
	configYAML := "storage:\n  type: local\n  database:\n    path: ./secrets.db\ncredential_delivery:\n  base_url: \"https://test.example.com\"\n  mode: out_of_band\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(configYAML), 0o600))

	_, targetID := seedUserDB(t)

	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID = targetID
	resendSetupLinkBy = "admin@example.com"

	out := captureOutput(t, func() {
		err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Setup link reissued")
	assert.Contains(t, out, "target@example.com")
}
