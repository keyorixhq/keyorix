package migrate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateCmd_Subcommands(t *testing.T) {
	want := map[string]bool{"user-to-machine": false}
	for _, c := range MigrateCmd.Commands() {
		want[c.Name()] = true
	}
	for name, found := range want {
		assert.True(t, found, "expected migrate subcommand %q to be registered", name)
	}
}

func TestUserToMachineCmd_Args(t *testing.T) {
	cmd, _, err := MigrateCmd.Find([]string{"user-to-machine"})
	require.NoError(t, err)
	// ExactArgs(1): zero args rejected, one accepted.
	assert.Error(t, cmd.Args(cmd, []string{}), "should require a username")
	assert.NoError(t, cmd.Args(cmd, []string{"ci-bot"}), "should accept one username")
}

func TestUserToMachineCmd_Flags(t *testing.T) {
	cmd, _, err := MigrateCmd.Find([]string{"user-to-machine"})
	require.NoError(t, err)
	for _, f := range []string{"project", "type", "name", "by", "keep-user"} {
		assert.NotNil(t, cmd.Flags().Lookup(f), "user-to-machine should have a --%s flag", f)
	}
}
