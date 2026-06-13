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
			fmt.Printf("No access to project %d's secrets.\n", flagProject)
			return nil
		}
		fmt.Printf("Access review — project %d (%d grant(s)):\n\n", flagProject, len(out.Entries))
		fmt.Printf("%-13s %-6s %-26s %-7s %s\n", "SOURCE", "TYPE", "PRINCIPAL", "ACCESS", "DETAIL")
		for _, e := range out.Entries {
			principal := e.PrincipalName
			if e.PrincipalType == "user" && e.Email != "" {
				principal = fmt.Sprintf("%s <%s>", e.PrincipalName, e.Email)
			}
			detail := ""
			switch e.Source {
			case "role":
				scope := "project"
				if e.EnvironmentID > 0 {
					scope = fmt.Sprintf("env=%d", e.EnvironmentID)
				}
				detail = fmt.Sprintf("role=%s (%s)", e.RoleName, scope)
			default: // owner / direct_share / group_share
				detail = "secret=" + e.SecretName
			}
			fmt.Printf("%-13s %-6s %-26s %-7s %s\n", e.Source, e.PrincipalType, truncate(principal, 26), e.AccessLevel, detail)
		}
		return nil
	},
}

type entryView struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   uint   `json:"principal_id"`
	PrincipalName string `json:"principal_name"`
	Email         string `json:"email"`
	Source        string `json:"source"`
	RoleID        uint   `json:"role_id"`
	RoleName      string `json:"role_name"`
	AccessLevel   string `json:"access_level"`
	EnvironmentID uint   `json:"environment_id"`
	SecretID      uint   `json:"secret_id"`
	SecretName    string `json:"secret_name"`
}

// decisionFlags are shared by the revoke and attest subcommands to identify one
// access-review entry. They mirror the columns the report prints.
var (
	dProject       int
	dSource        string
	dPrincipalType string
	dPrincipalID   uint
	dRoleID        uint
	dEnvironmentID uint
	dSecretID      uint
)

// decisionBody is the JSON sent to the revoke/attest endpoints.
type decisionBody struct {
	Source        string `json:"source"`
	PrincipalType string `json:"principal_type,omitempty"`
	PrincipalID   uint   `json:"principal_id"`
	RoleID        uint   `json:"role_id,omitempty"`
	EnvironmentID uint   `json:"environment_id,omitempty"`
	SecretID      uint   `json:"secret_id,omitempty"`
}

func runDecision(action string) error {
	if dProject <= 0 {
		return fmt.Errorf("--project-id is required")
	}
	if dSource == "" {
		return fmt.Errorf("--source is required (role|direct_share|group_share)")
	}
	if dPrincipalID == 0 {
		return fmt.Errorf("--principal-id is required")
	}
	if dSource == "role" && dRoleID == 0 {
		return fmt.Errorf("--role-id is required when --source=role")
	}
	if (dSource == "direct_share" || dSource == "group_share") && dSecretID == 0 {
		return fmt.Errorf("--secret-id is required when --source=%s", dSource)
	}
	c, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	body := decisionBody{
		Source: dSource, PrincipalType: dPrincipalType, PrincipalID: dPrincipalID,
		RoleID: dRoleID, EnvironmentID: dEnvironmentID, SecretID: dSecretID,
	}
	path := fmt.Sprintf("/api/v1/projects/%d/access-review/%s", dProject, action)
	var out struct{}
	if err := c.Post(context.Background(), path, body, &out); err != nil {
		return err
	}
	verb := "Revoked"
	if action == "attest" {
		verb = "Attested"
	}
	fmt.Printf("%s %s grant for %s %d in project %d.\n", verb, dSource, dPrincipalType, dPrincipalID, dProject)
	return nil
}

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an access-review grant (remove the role assignment or share)",
	Long: `Remove the grant identified by the flags — a project-scoped role assignment
(--source role --role-id N) or a secret share (--source direct_share|group_share
--secret-id N). The removal is audited (access_review.revoked). Requires
roles.assign at the project scope.`,
	SilenceUsage: true,
	RunE:         func(_ *cobra.Command, _ []string) error { return runDecision("revoke") },
}

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Attest an access-review grant (certify it was reviewed and kept)",
	Long: `Record that the grant identified by the flags was reviewed and intentionally
kept — the audit evidence of recertification (access_review.attested). Changes no
access. Requires roles.read at the project scope.`,
	SilenceUsage: true,
	RunE:         func(_ *cobra.Command, _ []string) error { return runDecision("attest") },
}

func addDecisionFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&dProject, "project-id", 0, "Project the grant belongs to (required)")
	cmd.Flags().StringVar(&dSource, "source", "", "Grant source: role|direct_share|group_share (required)")
	cmd.Flags().StringVar(&dPrincipalType, "principal-type", "user", "Principal type: user|group (for role grants)")
	cmd.Flags().UintVar(&dPrincipalID, "principal-id", 0, "User or group ID the grant is for (required)")
	cmd.Flags().UintVar(&dRoleID, "role-id", 0, "Role ID (required when --source=role)")
	cmd.Flags().UintVar(&dEnvironmentID, "environment-id", 0, "Environment scope of a role grant (0 = whole project)")
	cmd.Flags().UintVar(&dSecretID, "secret-id", 0, "Secret ID (required when --source=direct_share|group_share)")
}

func init() {
	AccessReviewCmd.Flags().IntVar(&flagProject, "project-id", 0, "Project to review (required)")
	addDecisionFlags(revokeCmd)
	addDecisionFlags(attestCmd)
	AccessReviewCmd.AddCommand(revokeCmd, attestCmd)
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
