package migrate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrateCmdWiring verifies the MigrateCmd wiring — already covered by
// migrate_test.go; this file adds additional flag-validation paths that are
// not yet exercised.

// TestUserToMachineCmd_TypeFlagDefault verifies the default value for --type.
func TestUserToMachineCmd_TypeFlagDefault(t *testing.T) {
	f := userToMachineCmd.Flags().Lookup("type")
	require.NotNil(t, f)
	assert.Equal(t, "service", f.DefValue)
}

// TestUserToMachineCmd_KeepUserFlagDefault verifies --keep-user defaults to false.
func TestUserToMachineCmd_KeepUserFlagDefault(t *testing.T) {
	f := userToMachineCmd.Flags().Lookup("keep-user")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue)
}

// TestUserToMachineCmd_ProjectFlagEmpty verifies --project default is "".
func TestUserToMachineCmd_ProjectFlagDefault(t *testing.T) {
	f := userToMachineCmd.Flags().Lookup("project")
	require.NotNil(t, f)
	assert.Equal(t, "", f.DefValue)
}

// TestRunUserToMachine_ByRequired_CobraBypassPath re-exercises the guard via the
// package-level var (already covered by migrate_extra_test.go; included here for
// package-level isolation clarity).
func TestRunUserToMachine_ByRequiredGuard(t *testing.T) {
	orig := u2mBy
	defer func() { u2mBy = orig }()
	u2mBy = ""

	err := runUserToMachine(userToMachineCmd, []string{"service-account"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acting admin email is required")
}

// TestMigrateCmd_UseField checks the Use field to guard against accidental renames.
func TestMigrateCmd_UseField(t *testing.T) {
	assert.Equal(t, "migrate", MigrateCmd.Use)
}

// TestUserToMachineCmd_UseField verifies the sub-command Use text.
func TestUserToMachineCmd_UseField(t *testing.T) {
	assert.Equal(t, "user-to-machine <username>", userToMachineCmd.Use)
}

// TestUserToMachineCmd_ByFlagIsRequired verifies cobra marks --by as required.
func TestUserToMachineCmd_ByFlagIsRequired(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	f := userToMachineCmd.Flags().Lookup("by")
	require.NotNil(t, f)
	assert.NotEmpty(t, f.Annotations[cobraRequired])
}
