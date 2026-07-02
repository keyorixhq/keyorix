package machine

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestConfirmRevoke pins the interactive confirmation gate `machine revoke` uses:
// revocation is terminal (the state machine has no transition out of
// core.MachineRevoked), so only an exact "yes" answer proceeds.
func TestConfirmRevoke(t *testing.T) {
	cases := []struct {
		name   string
		answer string
		want   bool
	}{
		{"exact yes confirms", "yes\n", true},
		{"empty input aborts", "\n", false},
		{"no aborts", "no\n", false},
		{"anything else aborts", "YES\n", false}, // case-sensitive, matches revoke-all's pattern
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "revoke"}
			cmd.SetIn(strings.NewReader(tc.answer))
			got := confirmRevoke(cmd, "ci-runner")
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestRevokeCmd_HasYesFlag pins that only `revoke` (irreversible) gets the --yes
// confirmation-skip flag; `suspend` (reversible via reactivate) must not.
func TestRevokeCmd_HasYesFlag(t *testing.T) {
	assert.NotNil(t, revokeCmd.Flags().Lookup("yes"), "revoke should have a --yes flag")
	assert.Nil(t, suspendCmd.Flags().Lookup("yes"), "suspend is reversible and should not have a --yes flag")
	assert.Nil(t, reactivateCmd.Flags().Lookup("yes"), "reactivate should not have a --yes flag")
}
