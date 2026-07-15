// Package breakglass provides `keyorix break-glass` — self-service emergency
// access (NIS2/DORA incident response). `activate` immediately self-grants the
// configured emergency role, time-bound, with a required justification (loudly
// audited, admins alerted); `list` and `revoke` are the review actions. Talks to
// /api/v1/projects/{id}/break-glass.
package breakglass

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

const (
	flagProjectID = "project-id"
)

var (
	bgProject    int
	bgJustify    string
	bgTTL        string
	bgActivation int
)

// BreakGlassCmd is the `keyorix break-glass` command.
var BreakGlassCmd = &cobra.Command{
	Use:   "break-glass",
	Short: "Self-service emergency access (incident response)",
	Long: `Activate emergency access to a project: immediately self-grant the configured
emergency role, time-bound and auto-expiring, with a written justification. Every
activation is loudly audited and alerts the project's admins. Use list/revoke to
review and end activations.`,
}

func bgBase(project int) string {
	return "/api/v1/projects/" + strconv.Itoa(project) + "/break-glass"
}

type activationView struct {
	ID            uint   `json:"id"`
	UserID        uint   `json:"user_id"`
	RoleName      string `json:"role_name"`
	Justification string `json:"justification"`
	State         string `json:"state"`
	ExpiresAt     string `json:"expires_at"`
	CreatedAt     string `json:"created_at"`
}

var activateCmd = &cobra.Command{
	Use:          "activate",
	Short:        "Activate emergency access (self-grant the emergency role, time-bound)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if bgProject <= 0 {
			return fmt.Errorf("--project-id is required")
		}
		if bgJustify == "" {
			return fmt.Errorf("--justification is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Activation activationView `json:"activation"`
		}
		body := map[string]string{"justification": bgJustify, "ttl": bgTTL}
		if err := c.Post(context.Background(), bgBase(bgProject), body, &out); err != nil {
			return err
		}
		fmt.Printf("Emergency access activated (id=%d): role %q until %s.\n",
			out.Activation.ID, out.Activation.RoleName, out.Activation.ExpiresAt)
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:          "list",
	Short:        "List a project's break-glass activations (for review)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if bgProject <= 0 {
			return fmt.Errorf("--project-id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Activations []activationView `json:"activations"`
			Count       int              `json:"count"`
		}
		if err := c.Get(context.Background(), bgBase(bgProject), &out); err != nil {
			return err
		}
		if out.Count == 0 {
			fmt.Printf("No break-glass activations for project %d.\n", bgProject)
			return nil
		}
		fmt.Printf("Break-glass activations — project %d:\n\n", bgProject)
		fmt.Printf("%-5s %-8s %-9s %-16s %-20s %s\n", "ID", "USER", "STATE", "ROLE", "EXPIRES", "JUSTIFICATION")
		for _, a := range out.Activations {
			fmt.Printf("%-5d %-8d %-9s %-16s %-20s %s\n", a.ID, a.UserID, a.State, truncate(a.RoleName, 16), a.ExpiresAt, a.Justification)
		}
		return nil
	},
}

var revokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke an active emergency grant early",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if bgProject <= 0 || bgActivation <= 0 {
			return fmt.Errorf("--project-id and --activation-id are required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		path := fmt.Sprintf("%s/%d/revoke", bgBase(bgProject), bgActivation)
		var out struct{}
		if err := c.Post(context.Background(), path, map[string]string{}, &out); err != nil {
			return err
		}
		fmt.Printf("Revoked break-glass activation %d in project %d.\n", bgActivation, bgProject)
		return nil
	},
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func init() {
	activateCmd.Flags().IntVar(&bgProject, flagProjectID, 0, "Project to activate emergency access for (required)")
	activateCmd.Flags().StringVar(&bgJustify, "justification", "", "Written reason for emergency access (required)")
	activateCmd.Flags().StringVar(&bgTTL, "ttl", "", "Grant lifetime override, e.g. 2h (default + capped by server config)")

	listCmd.Flags().IntVar(&bgProject, flagProjectID, 0, "Project (required)")

	revokeCmd.Flags().IntVar(&bgProject, flagProjectID, 0, "Project (required)")
	revokeCmd.Flags().IntVar(&bgActivation, "activation-id", 0, "Activation to revoke (required)")

	BreakGlassCmd.AddCommand(activateCmd, listCmd, revokeCmd)
}
