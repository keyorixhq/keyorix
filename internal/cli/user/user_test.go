package user

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// cobraRequired is the annotation key cobra uses to mark required flags.
const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"

func TestUserCommandStructure(t *testing.T) {
	assert.Equal(t, "user", UserCmd.Use)

	names := make([]string, 0)
	for _, c := range UserCmd.Commands() {
		names = append(names, c.Use)
	}
	for _, expected := range []string{
		"create", "get", "update", "delete", "list",
		"suspend", "reactivate", "force-password-reset", "revoke-sessions",
	} {
		assert.Contains(t, names, expected, "expected subcommand %q", expected)
	}
}

func TestLifecycleRequiredFlags(t *testing.T) {
	cmds := map[string]*cobra.Command{
		"suspend":              suspendCmd,
		"reactivate":           reactivateCmd,
		"force-password-reset": forcePasswordResetCmd,
		"revoke-sessions":      revokeSessionsCmd,
		"delete":               deleteCmd,
	}
	for label, c := range cmds {
		for _, name := range []string{"id", "by"} {
			f := c.Flags().Lookup(name)
			assert.NotNil(t, f, "%s should have --%s", label, name)
			if f != nil {
				assert.NotEmpty(t, f.Annotations[cobraRequired], "%s --%s should be required", label, name)
			}
		}
	}
}
