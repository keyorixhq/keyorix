package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCmd_NeitherIDNorEmail(t *testing.T) {
	origID, origEmail := getUserID, getUserEmail
	defer func() { getUserID = origID; getUserEmail = origEmail }()
	getUserID = 0
	getUserEmail = ""
	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id or --email")
}

func TestGetCmd_BothIDAndEmail(t *testing.T) {
	origID, origEmail := getUserID, getUserEmail
	defer func() { getUserID = origID; getUserEmail = origEmail }()
	getUserID = 1
	getUserEmail = "x@example.com"
	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of")
}

func TestUpdateCmd_IDRequired(t *testing.T) {
	orig := updateUserID
	defer func() { updateUserID = orig }()
	updateUserID = 0
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user id is required")
}

func TestUpdateCmd_NoFieldsProvided(t *testing.T) {
	origID, origU, origE, origD, origA := updateUserID, updateUsername, updateEmail, updateDisplayName, updateActiveStr
	defer func() {
		updateUserID = origID
		updateUsername = origU
		updateEmail = origE
		updateDisplayName = origD
		updateActiveStr = origA
	}()
	updateUserID = 1
	updateUsername = ""
	updateEmail = ""
	updateDisplayName = ""
	updateActiveStr = ""
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provide at least one of")
}

func TestUpdateCmd_InvalidActive(t *testing.T) {
	origID, origA := updateUserID, updateActiveStr
	defer func() { updateUserID = origID; updateActiveStr = origA }()
	updateUserID = 1
	updateActiveStr = "maybe"
	// At least one other field must be set to pass the "no fields" check.
	// active itself counts, so this reaches ParseBool.
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --active value")
}

func TestResendSetupLinkCmd_RequiredFlags(t *testing.T) {
	for _, name := range []string{"id", "by"} {
		f := resendSetupLinkCmd.Flags().Lookup(name)
		require.NotNil(t, f, "resend-setup-link should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestResendSetupLinkCmd_IDRequired(t *testing.T) {
	orig := resendSetupLinkUserID
	defer func() { resendSetupLinkUserID = orig }()
	resendSetupLinkUserID = 0
	resendSetupLinkBy = "admin@example.com"
	err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user id is required")
}

func TestResendSetupLinkCmd_ByRequired(t *testing.T) {
	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID = 1
	resendSetupLinkBy = ""
	err := resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acting admin email is required")
}

func TestRunLifecycle_IDRequired(t *testing.T) {
	err := runLifecycle(0, "admin@example.com", "suspended", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user id is required")
}

func TestRunLifecycle_ByRequired(t *testing.T) {
	err := runLifecycle(1, "", "suspended", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acting admin email is required")
}

func TestCreateCmd_SetupLinkXorOTP(t *testing.T) {
	origSL, origOTP, origUser, origEmail := createSetupLink, createOneTimePassword, createUsername, createEmail
	defer func() {
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createUsername = origUser
		createEmail = origEmail
	}()
	createUsername = "bob"
	createEmail = "bob@example.com"
	createSetupLink = true
	createOneTimePassword = true
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either --setup-link or --one-time-password, not both")
}

func TestUserGetFlags(t *testing.T) {
	assert.NotNil(t, getCmd.Flags().Lookup("id"))
	assert.NotNil(t, getCmd.Flags().Lookup("email"))
}

func TestUserUpdateFlags(t *testing.T) {
	for _, name := range []string{"id", "username", "email", "display-name", "active"} {
		assert.NotNil(t, updateCmd.Flags().Lookup(name), "update should have --%s", name)
	}
}

func TestUserListFlags(t *testing.T) {
	assert.NotNil(t, listCmd.Flags().Lookup("page"))
	assert.NotNil(t, listCmd.Flags().Lookup("page-size"))
}
