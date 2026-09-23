package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var mfaCmd = &cobra.Command{
	Use:   "mfa",
	Short: "Manage MFA (multi-factor authentication)",
}

var mfaStepUpCode string

var mfaStepUpCmd = &cobra.Command{
	Use:   "stepup",
	Short: "Re-verify your TOTP to unlock restricted secret reads",
	Long: `Re-verify your authenticator code (or a recovery code) without re-logging in.
On success, a 15-minute window is opened server-side that allows reading
"restricted" classified secrets.`,
	RunE: runMFAStepUp,
}

func init() {
	// --code is INSECURE on the command line (visible via ps/proc and saved in shell
	// history) -- same reasoning as loginCmd's --api-key. Omit it to be prompted.
	mfaStepUpCmd.Flags().StringVar(&mfaStepUpCode, "code", "", "TOTP or recovery code (INSECURE on the command line -- omit to be prompted)")
	mfaCmd.AddCommand(mfaStepUpCmd)
}

func runMFAStepUp(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("code") {
		fmt.Fprintln(os.Stderr, "Warning: --code is visible in your shell history and to other processes on this machine (ps/proc) -- prefer the interactive prompt.")
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("MFA step-up requires an active session -- run \"keyorix-next login\" first")
	}

	code := mfaStepUpCode
	if code == "" {
		code, err = promptLine("Enter TOTP or recovery code: ")
		if err != nil || code == "" {
			return fmt.Errorf("code is required")
		}
	}

	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	resp, err := client.MfaStepUpWithResponse(context.Background(), apiclient.MfaStepUpJSONRequestBody{Code: code})
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("MFA step-up failed: HTTP %d", resp.StatusCode())
	}

	fmt.Println("MFA step-up verified. Restricted secrets are accessible for 15 minutes.")
	return nil
}
