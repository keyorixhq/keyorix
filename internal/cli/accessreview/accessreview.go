// Package accessreview provides `keyorix access-review` — the role-based access
// recertification report for a project (ISO 27001 A.5.18 / SOC 2 CC6.2-6.3): who
// (user or group) can reach the project's secrets via an assigned role, and at
// what level. Talks to GET /api/v1/projects/{id}/access-review (gated by
// roles.read at the project scope).
package accessreview

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var flagProject int

// AccessReviewCmd is the `keyorix access-review` command.
var AccessReviewCmd = &cobra.Command{
	Use:     "access-review",
	Aliases: []string{"access-recert", "recert"},
	Short:   "Review who has role-based access to a project's secrets (ISO 27001 A.5.18)",
	Long: `List every principal (user or group) that can reach a project's secrets via an
assigned role, with the highest secrets action that role grants — the role-based
standing-access surface for periodic access recertification. Requires roles.read
at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if flagProject <= 0 {
			return fmt.Errorf("--project-id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Entries []entryView `json:"entries"`
			Count   int         `json:"count"`
		}
		if err := c.Get(context.Background(), "/api/v1/projects/"+strconv.Itoa(flagProject)+"/access-review", &out); err != nil {
			return err
		}
		if len(out.Entries) == 0 {
			fmt.Printf("No role-based access to project %d's secrets.\n", flagProject)
			return nil
		}
		fmt.Printf("Role-based access review — project %d (%d principal grant(s)):\n\n", flagProject, len(out.Entries))
		fmt.Printf("%-7s %-24s %-16s %-8s %s\n", "TYPE", "PRINCIPAL", "ROLE", "ACCESS", "SCOPE")
		for _, e := range out.Entries {
			scope := "project"
			if e.EnvironmentID > 0 {
				scope = fmt.Sprintf("env=%d", e.EnvironmentID)
			}
			principal := e.PrincipalName
			if e.PrincipalType == "user" && e.Email != "" {
				principal = fmt.Sprintf("%s <%s>", e.PrincipalName, e.Email)
			}
			fmt.Printf("%-7s %-24s %-16s %-8s %s\n", e.PrincipalType, truncate(principal, 24), e.RoleName, e.AccessLevel, scope)
		}
		return nil
	},
}

type entryView struct {
	PrincipalType string `json:"principal_type"`
	PrincipalName string `json:"principal_name"`
	Email         string `json:"email"`
	RoleName      string `json:"role_name"`
	AccessLevel   string `json:"access_level"`
	EnvironmentID uint   `json:"environment_id"`
}

func init() {
	AccessReviewCmd.Flags().IntVar(&flagProject, "project-id", 0, "Project to review (required)")
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
