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
// GET /projects/{id}/secrets/name-conformance report (snake_case DTO).
type nameConformanceViolation struct {
	ID            uint   `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	EnvironmentID uint   `json:"environment_id"`
	Reason        string `json:"reason"`
}

// nameConformanceReport mirrors the report envelope's data object.
type nameConformanceReport struct {
	PolicyEnabled bool                       `json:"policy_enabled"`
	Pattern       string                     `json:"pattern"`
	MaxLength     int                        `json:"max_length"`
	TotalSecrets  int                        `json:"total_secrets"`
	Violations    []nameConformanceViolation `json:"violations"`
}

var nameConformanceCmd = &cobra.Command{
	Use:   "name-conformance",
	Short: "List a project's secrets whose names violate the current naming policy",
	Long: `Show the live secrets whose names fail the current secret naming policy. The policy is
enforced only when a secret is created, so names can fall out of conformance after the
policy is added or tightened — this surfaces those stragglers so you can rename them.
Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if nameConformanceProject == 0 {
			return fmt.Errorf("--project is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		report, err := fetchNameConformance(context.Background(), c, nameConformanceProject)
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
		fmt.Printf("%-8s %-24s %-12s %s\n", "ID", "NAME", "TYPE", "REASON")
		for _, v := range report.Violations {
			fmt.Printf("%-8d %-24s %-12s %s\n", v.ID, v.Name, v.Type, v.Reason)
		}
		return nil
	},
}

// fetchNameConformance GETs the project's naming-policy conformance report
// (split out for httptest tests).
func fetchNameConformance(ctx context.Context, c *common.RemoteClient, projectID uint) (nameConformanceReport, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/name-conformance"
	var report nameConformanceReport
	if err := c.Get(ctx, path, &report); err != nil {
		return nameConformanceReport{}, err
	}
	return report, nil
}

func init() {
	nameConformanceCmd.Flags().UintVar(&nameConformanceProject, "project", 0, "Project ID (required)")
	SecretCmd.AddCommand(nameConformanceCmd)
}
