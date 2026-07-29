// mfa_stepup.go — CLI command for explicit MFA step-up re-verification.
// `keyorix auth mfa stepup --code <code>` lets an already-authenticated user
// re-verify their TOTP (or recovery code) to open the 15-minute read window
// for "restricted" classified secrets without going through a full re-login.
// Remote-only: the embedded mode has no active user session to step up.
package auth

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var mfaCmd = &cobra.Command{
	Use:   "mfa",
	Short: "Manage MFA (multi-factor authentication)",
	Long:  "Manage multi-factor authentication settings for your account",
}

var mfaStepUpCmd = &cobra.Command{
	Use:   "stepup",
	Short: "Re-verify your TOTP to unlock restricted secret reads",
	Long: `Re-verify your authenticator code (or a recovery code) without re-logging in.
On success, a 15-minute window is opened server-side that allows reading
"restricted" classified secrets.

This command requires an active session (remote mode only).`,
	RunE: runMFAStepUp,
}

func init() {
	mfaStepUpCmd.Flags().String("code", "", "TOTP or recovery code")

	mfaCmd.AddCommand(mfaStepUpCmd)
	AuthCmd.AddCommand(mfaCmd)
}

func runMFAStepUp(cmd *cobra.Command, _ []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("MFA step-up requires remote mode — run 'keyorix auth login' first")
	}

	code, _ := cmd.Flags().GetString("code")
	if code == "" {
		fmt.Print("Enter TOTP or recovery code: ")
		_, err := fmt.Scanln(&code) //nolint:errcheck
		if err != nil || code == "" {
			return fmt.Errorf("code is required")
		}
	}

	if err := rc.Post(context.Background(), "/api/v1/auth/mfa/stepup", map[string]string{"code": code}, nil); err != nil {
		return fmt.Errorf("MFA step-up failed: %w", err)
	}

	fmt.Println("MFA step-up verified. Restricted secrets are accessible for 15 minutes.")
	return nil
}
