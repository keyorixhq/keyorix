// breakglass.go ports `keyorix break-glass` (docs/cli-split-inventory.md §2.4, PR 1):
// self-service emergency access (NIS2/DORA incident response). Same flags, output, and
// exit codes as the old CLI's internal/cli/breakglass package -- this is a pure transport
// port (REST only, Zero GAPs), not a behavior change.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// breakGlassCmd is the `keyorix-next break-glass` command.
var breakGlassCmd = &cobra.Command{
	Use:   "break-glass",
	Short: "Self-service emergency access (incident response)",
	Long: `Activate emergency access to a project: immediately self-grant the configured
emergency role, time-bound and auto-expiring, with a written justification. Every
activation is loudly audited and alerts the project's admins. Use list/revoke to
review and end activations.`,
}

const bgFlagProjectID = "project-id"

var (
	bgProject    int
	bgJustify    string
	bgTTL        string
	bgActivation int
)

var bgActivateCmd = &cobra.Command{
	Use:          "activate",
	Short:        "Activate emergency access (self-grant the emergency role, time-bound)",
	SilenceUsage: true,
	RunE:         runBGActivate,
}

var bgListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List a project's break-glass activations (for review)",
	SilenceUsage: true,
	RunE:         runBGList,
}

var bgRevokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke an active emergency grant early",
	SilenceUsage: true,
	RunE:         runBGRevoke,
}

func init() {
	bgActivateCmd.Flags().IntVar(&bgProject, bgFlagProjectID, 0, "Project to activate emergency access for (required)")
	bgActivateCmd.Flags().StringVar(&bgJustify, "justification", "", "Written reason for emergency access (required)")
	bgActivateCmd.Flags().StringVar(&bgTTL, "ttl", "", "Grant lifetime override, e.g. 2h (default + capped by server config)")

	bgListCmd.Flags().IntVar(&bgProject, bgFlagProjectID, 0, "Project (required)")

	bgRevokeCmd.Flags().IntVar(&bgProject, bgFlagProjectID, 0, "Project (required)")
	bgRevokeCmd.Flags().IntVar(&bgActivation, "activation-id", 0, "Activation to revoke (required)")

	breakGlassCmd.AddCommand(bgActivateCmd, bgListCmd, bgRevokeCmd)
	rootCmd.AddCommand(breakGlassCmd)
}

// breakGlassAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every break-glass subcommand needs.
func breakGlassAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

func runBGActivate(_ *cobra.Command, _ []string) error {
	if bgProject <= 0 {
		return fmt.Errorf("--project-id is required")
	}
	if bgJustify == "" {
		return fmt.Errorf("--justification is required")
	}
	client, err := breakGlassAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.ActivateBreakGlassJSONRequestBody{Justification: bgJustify}
	if bgTTL != "" {
		body.Ttl = &bgTTL
	}
	resp, err := client.ActivateBreakGlassWithResponse(context.Background(), uint32(bgProject), body)
	if err != nil {
		return err
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.Activation == nil {
		return fmt.Errorf("activate break-glass failed: HTTP %d", resp.StatusCode())
	}
	a := resp.JSON201.Data.Activation
	fmt.Printf("Emergency access activated (id=%d): role %q until %s.\n",
		derefUint32(a.Id), derefStr(a.RoleName), derefStr(a.ExpiresAt))
	return nil
}

func runBGList(_ *cobra.Command, _ []string) error {
	if bgProject <= 0 {
		return fmt.Errorf("--project-id is required")
	}
	client, err := breakGlassAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListBreakGlassActivationsWithResponse(context.Background(), uint32(bgProject))
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || derefInt(resp.JSON200.Data.Count) == 0 {
		fmt.Printf("No break-glass activations for project %d.\n", bgProject)
		return nil
	}
	fmt.Printf("Break-glass activations — project %d:\n\n", bgProject)
	fmt.Printf("%-5s %-8s %-9s %-16s %-20s %s\n", "ID", "USER", "STATE", "ROLE", "EXPIRES", "JUSTIFICATION")
	var activations []apiclient.BreakGlassActivation
	if resp.JSON200.Data.Activations != nil {
		activations = *resp.JSON200.Data.Activations
	}
	for _, a := range activations {
		fmt.Printf("%-5d %-8d %-9s %-16s %-20s %s\n", derefUint32(a.Id), derefUint32(a.UserId),
			derefStr((*string)(a.State)), bgTruncate(derefStr(a.RoleName), 16), derefStr(a.ExpiresAt), derefStr(a.Justification))
	}
	return nil
}

func runBGRevoke(_ *cobra.Command, _ []string) error {
	if bgProject <= 0 || bgActivation <= 0 {
		return fmt.Errorf("--project-id and --activation-id are required")
	}
	client, err := breakGlassAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RevokeBreakGlassWithResponse(context.Background(), uint32(bgProject), uint32(bgActivation))
	if err != nil {
		return err
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return fmt.Errorf("revoke break-glass activation failed: HTTP %d", resp.StatusCode())
	}
	fmt.Printf("Revoked break-glass activation %d in project %d.\n", bgActivation, bgProject)
	return nil
}

func bgTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
