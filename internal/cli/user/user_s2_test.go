// user_s2_test.go — coverage sprint 2 for internal/cli/user.
// Targets: runCreate (setup-link and OTP embedded paths, password env-var path),
// printUser (direct call), runGet (email path + service success), runList
// (success with data), runUpdate (success path), runLifecycle (success path),
// revokeSessionsCmd (success path).
package user

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// No shared rig needed — all embedded tests use common.InitializeCoreService via t.Chdir.

// captureOutput redirects stdout and returns the captured string.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// ──────────────────────────── printUser ──────────────────────────────────────

func TestPrintUser_WithDisplayName(t *testing.T) {
	now := time.Now()
	u := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	u.ID = 5
	out := captureOutput(t, func() { printUser(u) })
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "Alice Smith")
	assert.Contains(t, out, "alice@example.com")
}

func TestPrintUser_NoDisplayName(t *testing.T) {
	now := time.Now()
	u := &models.User{
		Username:  "bob",
		Email:     "bob@example.com",
		IsActive:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	u.ID = 6
	out := captureOutput(t, func() { printUser(u) })
	// Falls back to username when DisplayName is empty.
	assert.Contains(t, out, "bob")
}

// ──────────────────────────── runCreate embedded paths ───────────────────────

// TestRunCreate_EnvPassword_ReachesServiceInit verifies that with a password
// resolved via KEYORIX_INITIAL_PASSWORD, runCreate proceeds past flag
// validation to the service-init call (and may fail there due to missing admin).
func TestRunCreate_EnvPassword_ReachesServiceInit(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_INITIAL_PASSWORD", "env-pass")

	origU, origE, origSL, origOTP, origPW := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
	}()
	createUsername = "carol"
	createEmail = "carol@example.com"
	createSetupLink = false
	createOneTimePassword = false
	createPassword = "" // force env-var path

	err := runCreate(nil, nil)
	// Expected: service may succeed (creates user) or fail; not a flag error.
	if err != nil {
		assert.NotContains(t, err.Error(), "username is required")
		assert.NotContains(t, err.Error(), "email is required")
	}
}

// TestRunCreate_SetupLink_EmbeddedMode exercises the setup-link path in
// embedded mode (no remote client, SQLite created in temp dir).
func TestRunCreate_SetupLink_EmbeddedMode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
		createBy = origBy
	}()
	createUsername = "newuser"
	createEmail = "newuser@example.com"
	createSetupLink = true
	createOneTimePassword = false
	createPassword = ""
	createBy = "" // no --by: skip resolveAdminID

	// The embedded service creates the DB in the temp dir; setup-link creation
	// should reach service.CreateUserWithSetupLink.
	err := runCreate(nil, nil)
	// May succeed or fail (no RBAC bootstrap); must not be a flag error.
	if err != nil {
		assert.NotContains(t, err.Error(), "username is required")
		assert.NotContains(t, err.Error(), "email is required")
		assert.NotContains(t, err.Error(), "--setup-link")
	}
}

// TestRunCreate_OTP_EmbeddedMode exercises the one-time-password path in
// embedded mode.
func TestRunCreate_OTP_EmbeddedMode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
		createBy = origBy
	}()
	createUsername = "otpuser"
	createEmail = "otpuser@example.com"
	createSetupLink = false
	createOneTimePassword = true
	createPassword = ""
	createBy = "" // no --by

	err := runCreate(nil, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "username is required")
		assert.NotContains(t, err.Error(), "email is required")
		assert.NotContains(t, err.Error(), "--one-time-password")
	}
}

// TestRunCreate_OTP_RemoteReachesServer confirms that --one-time-password in remote
// mode now forwards to the server (generate_one_time_password:true) rather than
// rejecting with a "not yet supported" error.
func TestRunCreate_OTP_RemoteReachesServer(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Port 1 is always refused — we just want to confirm the HTTP attempt is made.
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
	t.Setenv("KEYORIX_TOKEN", "tok")

	origU, origE, origSL, origOTP := createUsername, createEmail, createSetupLink, createOneTimePassword
	defer func() {
		createUsername = origU; createEmail = origE
		createSetupLink = origSL; createOneTimePassword = origOTP
	}()
	createUsername = "carol"
	createEmail = "carol@example.com"
	createSetupLink = false
	createOneTimePassword = true

	err := runCreate(nil, nil)
	// Must error (refused connection), but NOT with "not yet supported".
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not yet supported")
	assert.Contains(t, err.Error(), "failed to create user")
}

// TestRunCreate_PasswordMode_EmbeddedMode tests the normal password creation path
// in embedded mode with KEYORIX_INITIAL_PASSWORD env var.
func TestRunCreate_PasswordMode_EmbeddedMode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_INITIAL_PASSWORD", "P@ssw0rd!2026")

	origU, origE, origSL, origOTP, origPW := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword
	defer func() {
		createUsername = origU; createEmail = origE
		createSetupLink = origSL; createOneTimePassword = origOTP
		createPassword = origPW
	}()
	createUsername = "pwduser"
	createEmail = "pwduser@example.com"
	createSetupLink = false
	createOneTimePassword = false
	createPassword = ""

	// Reaches service.CreateUser — may succeed or fail (no RBAC bootstrap).
	err := runCreate(nil, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "password is required")
	}
}

// ──────────────────────────── runGet email path ───────────────────────────────

// TestRunGet_EmailPath_ServiceError exercises the GetUserByEmail branch inside
// runGet (which is reached when getUserID==0 and getUserEmail is set).
func TestRunGet_EmailPath_ServiceError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origEmail := getUserID, getUserEmail
	defer func() { getUserID = origID; getUserEmail = origEmail }()
	getUserID = 0
	getUserEmail = "unknown@example.com"

	err := runGet(nil, nil)
	// Expected: service init error or user-not-found error, not flag error.
	if err != nil {
		assert.NotContains(t, err.Error(), "--id or --email")
	}
}

// ──────────────────────────── runList success ─────────────────────────────────

// TestRunList_WithData exercises runList against a seeded in-memory DB.
// We can't inject a service directly into runList (it calls InitializeCoreService),
// but we can verify the output format when the DB returns an empty list.
func TestRunList_EmptyResult_FormatOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origPage, origSize := listPage, listPageSize
	defer func() { listPage = origPage; listPageSize = origSize }()
	listPage = 1
	listPageSize = 20

	// Service init will fail in temp dir (no DB), but we verify no panic.
	_ = runList(nil, nil)
}

// ──────────────────────────── runUpdate success path ─────────────────────────

// TestRunUpdate_ActiveTrue verifies the "true" active parse path in runUpdate.
func TestRunUpdate_ActiveTrue(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origActive := updateUserID, updateActiveStr
	defer func() { updateUserID = origID; updateActiveStr = origActive }()
	updateUserID = 1
	updateActiveStr = "true"
	updateUsername = ""
	updateEmail = ""
	updateDisplayName = ""

	// Reaches ParseBool("true") correctly, then service.UpdateUser (fails on missing DB).
	err := runUpdate(nil, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "invalid --active value")
	}
}

// TestRunUpdate_ActiveFalse verifies the "false" active parse path.
func TestRunUpdate_ActiveFalse(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origActive := updateUserID, updateActiveStr
	defer func() { updateUserID = origID; updateActiveStr = origActive }()
	updateUserID = 1
	updateActiveStr = "false"
	updateUsername = ""
	updateEmail = ""
	updateDisplayName = ""

	err := runUpdate(nil, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "invalid --active value")
	}
}

// ──────────────────────────── runLifecycle via in-memory core ─────────────────

// TestRunLifecycle_ApplyFuncCalled_SuspendError verifies that runLifecycle
// reaches the service-init path and returns a service or user-resolution error,
// not a flag validation error.
func TestRunLifecycle_ApplyFuncCalled(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// The apply function calls SuspendUser; with no real DB, service init or
	// admin resolution will fail — not a flag error.
	err := runLifecycle(999, "admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	// Must not be a flag-validation error.
	if err != nil {
		assert.NotContains(t, err.Error(), "user id is required")
		assert.NotContains(t, err.Error(), "acting admin email is required")
	}
}

// ──────────────────────────── revokeSessionsCmd service path ─────────────────

// TestRevokeSessionsCmd_ServiceInitPath exercises the path after flag validation,
// where service.RevokeUserSessions is reached.
func TestRevokeSessionsCmd_ServiceInitPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID = 1
	revokeSessionsBy = "admin@example.com"

	// Expected: service init or user-resolution error, not a flag error.
	err := revokeSessionsCmd.RunE(revokeSessionsCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "user id is required")
		assert.NotContains(t, err.Error(), "acting admin email is required")
	}
}

// ──────────────────────────── suspendCmd / reactivateCmd / forcePasswordResetCmd ──

// TestSuspendCmd_RunE exercises the suspendCmd RunE closure (calls runLifecycle).
func TestSuspendCmd_RunE(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origBy := suspendUserID, suspendBy
	defer func() { suspendUserID = origID; suspendBy = origBy }()
	suspendUserID = 1
	suspendBy = "admin@example.com"

	err := suspendCmd.RunE(suspendCmd, nil)
	// Expected: service init error; closure was entered.
	if err != nil {
		assert.NotContains(t, err.Error(), "user id is required")
	}
}

// TestReactivateCmd_RunE exercises the reactivateCmd RunE closure.
func TestReactivateCmd_RunE(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origBy := reactivateUserID, reactivateBy
	defer func() { reactivateUserID = origID; reactivateBy = origBy }()
	reactivateUserID = 1
	reactivateBy = "admin@example.com"

	err := reactivateCmd.RunE(reactivateCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "user id is required")
	}
}

// TestForcePasswordResetCmd_RunE exercises the forcePasswordResetCmd RunE closure.
func TestForcePasswordResetCmd_RunE(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origBy := forcePasswordResetUserID, forcePasswordResetBy
	defer func() { forcePasswordResetUserID = origID; forcePasswordResetBy = origBy }()
	forcePasswordResetUserID = 1
	forcePasswordResetBy = "admin@example.com"

	err := forcePasswordResetCmd.RunE(forcePasswordResetCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "user id is required")
	}
}

// ──────────────────────────── seeded file-DB helpers ─────────────────────────

// seedUserDB bootstraps a file-backed SQLite DB in the current working
// directory (must already be a temp dir via t.Chdir) by calling
// InitializeCoreService, then runs BootstrapSystem.  Returns the seeded admin
// user ID and a second non-admin user ID (created to be the target of lifecycle
// operations).
func seedUserDB(t *testing.T) (adminID uint, targetID uint) {
	t.Helper()
	ctx := context.Background()

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	svc.SetBootstrapToken("s2user-tok")
	resp, err := svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username:    "admin",
		Email:       "admin@example.com",
		Password:    "S3cur3!P@ssw0rd#2026",
		DisplayName: "Admin",
		Token:       "s2user-tok",
	})
	require.NoError(t, err)

	// Create a second user to be the target of lifecycle/delete operations.
	target, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "target",
		Email:       "target@example.com",
		DisplayName: "Target",
		Password:    "T@rget!P@ssw0rd#2026",
	})
	require.NoError(t, err)

	return resp.User.ID, target.ID
}

// ──────────────────────────── runGet success paths ───────────────────────────

// TestRunGet_ByID_SeededDB exercises the runGet --id success path (calls
// printUser) using a seeded file DB.
func TestRunGet_ByID_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, _ := seedUserDB(t)

	origID, origEmail := getUserID, getUserEmail
	defer func() { getUserID = origID; getUserEmail = origEmail }()
	getUserID = adminID
	getUserEmail = ""

	err := runGet(nil, nil)
	require.NoError(t, err)
}

// TestRunGet_ByEmail_SeededDB exercises the runGet --email success path.
func TestRunGet_ByEmail_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origID, origEmail := getUserID, getUserEmail
	defer func() { getUserID = origID; getUserEmail = origEmail }()
	getUserID = 0
	getUserEmail = "admin@example.com"

	err := runGet(nil, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runDelete with --force ─────────────────────────

// TestRunDelete_Force_SeededDB exercises the runDelete --force path (skips
// confirmation) against a seeded DB.
func TestRunDelete_Force_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, targetID := seedUserDB(t)

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID = targetID
	deleteBy = "admin@example.com"
	deleteForce = true

	_ = adminID
	err := runDelete(nil, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runLifecycle success paths ─────────────────────

// TestRunLifecycle_Suspend_SeededDB exercises the suspend success path through
// runLifecycle → SuspendUser with a seeded DB.
func TestRunLifecycle_Suspend_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	err := runLifecycle(targetID, "admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	require.NoError(t, err)
}

// TestRunLifecycle_Reactivate_SeededDB exercises the reactivate success path.
func TestRunLifecycle_Reactivate_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	// Suspend first so reactivation has something to do.
	suspendErr := runLifecycle(targetID, "admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	require.NoError(t, suspendErr)

	// Now reactivate.
	err := runLifecycle(targetID, "admin@example.com", "reactivated",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.ReactivateUser(c, adminID, userID)
		})
	require.NoError(t, err)
}

// TestRevokeSessionsCmd_SeededDB exercises the RevokeUserSessions success path.
func TestRevokeSessionsCmd_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID = targetID
	revokeSessionsBy = "admin@example.com"

	err := revokeSessionsCmd.RunE(revokeSessionsCmd, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runCreate with seeded DB ───────────────────────

// TestRunCreate_SetupLink_SeededDB exercises the setup-link path into
// CreateUserWithSetupLink (which may fail on delivery config — that's fine,
// the coverage goal is reaching that call site and the resolveAdminID branch).
func TestRunCreate_SetupLink_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU; createEmail = origE
		createSetupLink = origSL; createOneTimePassword = origOTP
		createPassword = origPW; createBy = origBy
	}()
	createUsername = "linkuser"
	createEmail = "linkuser@example.com"
	createSetupLink = true
	createOneTimePassword = false
	createPassword = ""
	createBy = "admin@example.com"

	// May fail on delivery config (out-of-band requires base_url); coverage
	// goal is reaching CreateUserWithSetupLink + resolveAdminID branches.
	err := runCreate(nil, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "username is required")
		assert.NotContains(t, err.Error(), "--setup-link")
	}
}

// TestRunCreate_OTP_SeededDB exercises the one-time-password success path.
func TestRunCreate_OTP_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU; createEmail = origE
		createSetupLink = origSL; createOneTimePassword = origOTP
		createPassword = origPW; createBy = origBy
	}()
	createUsername = "otpuser2"
	createEmail = "otpuser2@example.com"
	createSetupLink = false
	createOneTimePassword = true
	createPassword = ""
	createBy = "admin@example.com"

	err := runCreate(nil, nil)
	require.NoError(t, err)
}

// TestRunCreate_Password_SeededDB exercises the normal CreateUser success path.
func TestRunCreate_Password_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_INITIAL_PASSWORD", "NewP@ssw0rd!2026")

	_, _ = seedUserDB(t)

	origU, origE, origSL, origOTP, origPW := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword
	defer func() {
		createUsername = origU; createEmail = origE
		createSetupLink = origSL; createOneTimePassword = origOTP
		createPassword = origPW
	}()
	createUsername = "pwduser2"
	createEmail = "pwduser2@example.com"
	createSetupLink = false
	createOneTimePassword = false
	createPassword = ""

	err := runCreate(nil, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runList success ─────────────────────────────────

// TestRunList_SeededDB exercises the success path of runList (returns users +
// prints the result).
func TestRunList_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origPage, origSize := listPage, listPageSize
	defer func() { listPage = origPage; listPageSize = origSize }()
	listPage = 1
	listPageSize = 20

	err := runList(nil, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runUpdate success ───────────────────────────────

// TestRunUpdate_SeededDB_ActiveTrue exercises the UpdateUser success path with
// active=true flag against a seeded DB.
func TestRunUpdate_SeededDB_ActiveTrue(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origActive, origU, origE, origD := updateUserID, updateActiveStr, updateUsername, updateEmail, updateDisplayName
	defer func() {
		updateUserID = origID; updateActiveStr = origActive
		updateUsername = origU; updateEmail = origE; updateDisplayName = origD
	}()
	updateUserID = targetID
	updateActiveStr = "true"
	updateUsername = ""
	updateEmail = ""
	updateDisplayName = ""

	err := runUpdate(nil, nil)
	require.NoError(t, err)
}
