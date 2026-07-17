// user_s25_test.go — coverage sprint 25 for internal/cli/user.
// Targets the remaining ~10 % gap:
//   - runDelete with prompt confirmed ("yes") → actual delete
//   - runUpdate with non-active field paths (email, display-name, username)
//   - runLifecycle → RequirePasswordReset success path
//   - resendSetupLinkCmd.RunE service path (seeded DB)
//   - createBy bad-email error in --setup-link path
//   - createBy bad-email error in --one-time-password path
//   - runLifecycle apply-func error propagation ("failed: …")
package user

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── runDelete — confirmed prompt ───────────────────

// TestRunDelete_ConfirmYes_SeededDB exercises the non-force delete path where
// the operator types "yes" and the deletion succeeds.
func TestRunDelete_ConfirmYes_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID = targetID
	deleteBy = "admin@example.com"
	deleteForce = false

	// Provide "yes" on stdin so the confirmation is accepted.
	var err error
	withStdin(t, "yes\n", func() {
		err = runDelete(nil, nil)
	})
	require.NoError(t, err)
}

// TestRunDelete_ConfirmNo_SeededDB verifies that answering "no" cancels the
// deletion without error.
func TestRunDelete_ConfirmNo_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID = targetID
	deleteBy = "admin@example.com"
	deleteForce = false

	// "no" → cancelled without error.
	var err error
	withStdin(t, "no\n", func() {
		err = runDelete(nil, nil)
	})
	require.NoError(t, err)
}

// ──────────────────────────── runUpdate — individual field paths ─────────────

// TestRunUpdate_Email_SeededDB exercises the UpdateUser path when only the
// email field is supplied.
func TestRunUpdate_Email_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origU, origE, origD, origA := updateUserID, updateUsername, updateEmail, updateDisplayName, updateActiveStr
	defer func() {
		updateUserID = origID
		updateUsername = origU
		updateEmail = origE
		updateDisplayName = origD
		updateActiveStr = origA
	}()
	updateUserID = targetID
	updateUsername = ""
	updateEmail = "updated@example.com"
	updateDisplayName = ""
	updateActiveStr = ""

	err := runUpdate(nil, nil)
	require.NoError(t, err)
}

// TestRunUpdate_DisplayName_SeededDB exercises the UpdateUser path when only
// the display-name field is supplied.
func TestRunUpdate_DisplayName_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origU, origE, origD, origA := updateUserID, updateUsername, updateEmail, updateDisplayName, updateActiveStr
	defer func() {
		updateUserID = origID
		updateUsername = origU
		updateEmail = origE
		updateDisplayName = origD
		updateActiveStr = origA
	}()
	updateUserID = targetID
	updateUsername = ""
	updateEmail = ""
	updateDisplayName = "New Display Name"
	updateActiveStr = ""

	err := runUpdate(nil, nil)
	require.NoError(t, err)
}

// TestRunUpdate_Username_SeededDB exercises the UpdateUser path when only the
// username field is supplied.
func TestRunUpdate_Username_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origU, origE, origD, origA := updateUserID, updateUsername, updateEmail, updateDisplayName, updateActiveStr
	defer func() {
		updateUserID = origID
		updateUsername = origU
		updateEmail = origE
		updateDisplayName = origD
		updateActiveStr = origA
	}()
	updateUserID = targetID
	updateUsername = "renameduser"
	updateEmail = ""
	updateDisplayName = ""
	updateActiveStr = ""

	err := runUpdate(nil, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runLifecycle — RequirePasswordReset ────────────

// TestRunLifecycle_ForcePasswordReset_SeededDB exercises the RequirePasswordReset
// success path through runLifecycle.
func TestRunLifecycle_ForcePasswordReset_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	err := runLifecycle(targetID, "admin@example.com", "required to reset their password",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.RequirePasswordReset(c, adminID, userID)
		})
	require.NoError(t, err)
}

// TestForcePasswordResetCmd_RunE_SeededDB exercises the forcePasswordResetCmd
// RunE closure against a seeded DB (success path for the command wrapper).
func TestForcePasswordResetCmd_RunE_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origBy := forcePasswordResetUserID, forcePasswordResetBy
	defer func() { forcePasswordResetUserID = origID; forcePasswordResetBy = origBy }()
	forcePasswordResetUserID = targetID
	forcePasswordResetBy = "admin@example.com"

	err := forcePasswordResetCmd.RunE(forcePasswordResetCmd, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runLifecycle — apply func error ────────────────

// TestRunLifecycle_ApplyFuncError_Propagates verifies that an error returned
// by the apply function is wrapped and returned with "failed: " prefix.
func TestRunLifecycle_ApplyFuncError_Propagates(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	// Attempt to suspend a non-existent user (ID 99999): resolveAdminID will
	// succeed (admin exists) and apply will fail with a service error.
	err := runLifecycle(99999, "admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed")
}

// ──────────────────────────── resendSetupLinkCmd — service path ──────────────

// TestResendSetupLinkCmd_ServicePath_SeededDB exercises the resendSetupLinkCmd
// RunE past flag validation into the service call. The operation may fail at
// the delivery layer (no SMTP configured); the coverage goal is reaching
// service.ResendAccountSetupLink and the resolveAdminID branch.
func TestResendSetupLinkCmd_ServicePath_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Create a user in pending_first_login state so ResendAccountSetupLink
	// can find a valid target.
	_, targetID := seedUserDB(t)

	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID = targetID
	resendSetupLinkBy = "admin@example.com"

	// May succeed (out-of-band mode prints link) or fail (delivery error).
	// The flag-validation branches are already covered; here we verify the
	// resolveAdminID + service-call branch is entered.
	err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
	// Service errors are acceptable; flag errors are not.
	if err != nil {
		assert.NotContains(t, err.Error(), "user id is required")
		assert.NotContains(t, err.Error(), "acting admin email is required")
	}
}

// TestResendSetupLinkCmd_BadAdminEmail_SeededDB verifies that an unknown --by
// email produces a resolveAdminID error (not a flag-validation error).
func TestResendSetupLinkCmd_BadAdminEmail_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID = targetID
	resendSetupLinkBy = "nobody@example.com"

	err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nobody@example.com")
}

// ──────────────────────────── runCreate --by error paths ─────────────────────

// TestRunCreate_SetupLink_BadBy_SeededDB verifies that an unknown --by email
// on the setup-link path returns a resolveAdminID error.
func TestRunCreate_SetupLink_BadBy_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
		createBy = origBy
	}()
	createUsername = "slbadby"
	createEmail = "slbadby@example.com"
	createSetupLink = true
	createOneTimePassword = false
	createPassword = ""
	createBy = "ghost@example.com" // unknown admin

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost@example.com")
}

// TestRunCreate_OTP_BadBy_SeededDB verifies that an unknown --by email on the
// one-time-password path returns a resolveAdminID error.
func TestRunCreate_OTP_BadBy_SeededDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedUserDB(t)

	origU, origE, origSL, origOTP, origPW, origBy := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword, createBy
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
		createBy = origBy
	}()
	createUsername = "otpbadby"
	createEmail = "otpbadby@example.com"
	createSetupLink = false
	createOneTimePassword = true
	createPassword = ""
	createBy = "ghost@example.com" // unknown admin

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost@example.com")
}
