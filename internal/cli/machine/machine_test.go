package machine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineCmd_Subcommands(t *testing.T) {
	want := map[string]bool{
		"list": false, "create": false, "describe": false,
		"suspend": false, "reactivate": false, "revoke": false,
	}
	for _, c := range MachineCmd.Commands() {
		want[c.Name()] = true
	}
	for name, found := range want {
		assert.True(t, found, "expected machine subcommand %q to be registered", name)
	}
}

func TestMachineCmd_LifecycleCommandsTakeOneArg(t *testing.T) {
	for _, name := range []string{"suspend", "reactivate", "revoke", "describe"} {
		cmd, _, err := MachineCmd.Find([]string{name})
		require.NoError(t, err)
		// ExactArgs(1): zero args must be rejected, one accepted.
		assert.Error(t, cmd.Args(cmd, []string{}), "%s should require a ref", name)
		assert.NoError(t, cmd.Args(cmd, []string{"my-runner"}), "%s should accept one ref", name)
	}
}

func TestMachineCmd_ProjectFlag(t *testing.T) {
	for _, name := range []string{"list", "create", "describe", "suspend", "reactivate", "revoke"} {
		cmd, _, err := MachineCmd.Find([]string{name})
		require.NoError(t, err)
		assert.NotNil(t, cmd.Flags().Lookup("project"), "%s should have a --project flag", name)
	}
}
