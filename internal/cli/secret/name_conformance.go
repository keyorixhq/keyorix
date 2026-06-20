package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var nameConformanceProject uint

// nameConformanceViolation mirrors one violation in the
// GET /projects/{id}/secrets/name-conformance report (snake_case DTO). The org-wide
// report adds project_id/project_name, captured here too (zero for the project view).
type nameConformanceViolation struct {
	ID            uint   `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	EnvironmentID uint   `json:"environment_id"`
	Reason        string `json:"reason"`
	ProjectName   string `json:"project_name"`
}

// nameConformanceReport mirrors the report envelope's data object (both the per-project
// and the deployment-wide shapes; the latter tags each violation with its project).
type nameConformanceReport struct {
	PolicyEnabled bool                       `json:"policy_enabled"`
	Pattern       string                     `json:"pattern"`
	MaxLength     int                        `json:"max_length"`
	TotalSecrets  int                        `json:"total_secrets"`
	Violations    []nameConformanceViolation `json:"violations"`
}

var nameConformanceCmd = &cobra.Command{
	Use:   "name-conformance",
	Short: "List secrets whose names violate the current naming policy",
	Long: `Show the live secrets whose names fail the current secret naming policy. The policy is
enforced only when a secret is created, so names can fall out of conformance after the
policy is added or tightened — this surfaces those stragglers so you can rename them.

With --project, scopes to one project (requires secrets.read at the project scope).
Without --project, reports across every project (requires system.read — admin view).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		orgWide := nameConformanceProject == 0
		var report nameConformanceReport
		var err error
		if orgWide {
			report, err = fetchDeploymentNameConformance(context.Background(), c)
		} else {
			report, err = fetchNameConformance(context.Background(), c, nameConformanceProject)
		}
		if err != nil {
			return err
		}

		if !report.PolicyEnabled {
			fmt.Println("No secret naming policy is configured — nothing to check.")
			return nil
		}
		if len(report.Violations) == 0 {
			fmt.Printf("All %d secret(s) conform to the naming policy.\n", report.TotalSecrets)
			return nil
		}
		fmt.Printf("%d of %d secret(s) violate the naming policy:\n\n", len(report.Violations), report.TotalSecrets)
		if orgWide {
			fmt.Printf("%-20s %-8s %-24s %-12s %s\n", "PROJECT", "ID", "NAME", "TYPE", "REASON")
			for _, v := range report.Violations {
				fmt.Printf("%-20s %-8d %-24s %-12s %s\n", v.ProjectName, v.ID, v.Name, v.Type, v.Reason)
			}
		} else {
			fmt.Printf("%-8s %-24s %-12s %s\n", "ID", "NAME", "TYPE", "REASON")
			for _, v := range report.Violations {
				fmt.Printf("%-8d %-24s %-12s %s\n", v.ID, v.Name, v.Type, v.Reason)
			}
		}
		return nil
	},
}

// fetchNameConformance GETs a project's naming-policy conformance report
// (split out for httptest tests).
func fetchNameConformance(ctx context.Context, c *common.RemoteClient, projectID uint) (nameConformanceReport, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/name-conformance"
	var report nameConformanceReport
	if err := c.Get(ctx, path, &report); err != nil {
		return nameConformanceReport{}, err
	}
	return report, nil
}

// fetchDeploymentNameConformance GETs the org-wide naming-policy conformance report
// (split out for httptest tests).
func fetchDeploymentNameConformance(ctx context.Context, c *common.RemoteClient) (nameConformanceReport, error) {
	var report nameConformanceReport
	if err := c.Get(ctx, "/api/v1/secrets/name-conformance", &report); err != nil {
		return nameConformanceReport{}, err
	}
	return report, nil
}

func init() {
	nameConformanceCmd.Flags().UintVar(&nameConformanceProject, "project", 0, "Project ID (omit for an org-wide admin view)")
	SecretCmd.AddCommand(nameConformanceCmd)
}
