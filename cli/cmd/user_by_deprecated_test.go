package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// --by on the account-lifecycle commands is never sent to the server (the session is the
// actor): it must stay optional and deprecated until it is deleted (SUBTRACT-202611).
func TestUserLifecycleBy_IsOptionalAndDeprecated(t *testing.T) {
	for name, c := range map[string]*cobra.Command{
		"delete":               userDeleteCmd,
		"suspend":              userSuspendCmd,
		"reactivate":           userReactivateCmd,
		"force-password-reset": userForcePasswordResetCmd,
		"revoke-sessions":      userRevokeSessionsCmd,
		"resend-setup-link":    userResendSetupLinkCmd,
	} {
		f := c.Flags().Lookup("by")
		if f == nil {
			t.Errorf("user %s: --by flag missing", name)
			continue
		}
		if _, req := f.Annotations[cobra.BashCompOneRequiredFlag]; req {
			t.Errorf("user %s: --by must not be required", name)
		}
		if f.Deprecated == "" {
			t.Errorf("user %s: --by must be marked deprecated", name)
		}
	}
}
