// blast_radius.go — the `keyorix secret blast-radius` CLI (ADR-052 extension).
//
// Fetches the enriched blast-radius report from
// GET /api/v1/secrets/{id}/blast-radius and prints a human-readable tree of
// downstream dependents, their hop depth, and their risk level.
package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

type blastRadiusNodeView struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	ProjectID  uint   `json:"project_id"`
	OwnerID    uint   `json:"owner_id"`
	Depth      int    `json:"depth"`
	RiskLevel  string `json:"risk_level"`
}

type blastRadiusReportView struct {
	SourceSecretID   uint                  `json:"source_secret_id"`
	SourceSecretName string                `json:"source_secret_name"`
	Dependents       []blastRadiusNodeView `json:"dependents"`
	TotalImpact      int                   `json:"total_impact"`
	MaxDepth         int                   `json:"max_depth"`
}

var blastRadiusCmd = &cobra.Command{
	Use:          "blast-radius <secret-id>",
	Short:        "Show the enriched blast radius of rotating or deleting a secret",
	Long: `Show all downstream dependents of a secret (recursive), each annotated with
owner, project, hop depth, and risk level (critical/high/medium/low). Useful
for triage before a rotation or deletion event.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := blastRadiusClient()
		if err != nil {
			return err
		}
		report, err := fetchBlastRadius(context.Background(), c, id)
		if err != nil {
			return err
		}
		printBlastRadius(report)
		return nil
	},
}

func blastRadiusClient() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

func fetchBlastRadius(ctx context.Context, c *common.RemoteClient, id uint) (*blastRadiusReportView, error) {
	var report blastRadiusReportView
	if err := c.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d/blast-radius", id), &report); err != nil {
		return nil, err
	}
	return &report, nil
}

func printBlastRadius(report *blastRadiusReportView) {
	if report.TotalImpact == 0 {
		fmt.Printf("No dependents found for secret %q (id %d).\n", report.SourceSecretName, report.SourceSecretID)
		return
	}
	fmt.Printf("Blast radius of %q (id %d): %d dependent(s), max depth %d\n",
		report.SourceSecretName, report.SourceSecretID, report.TotalImpact, report.MaxDepth)
	fmt.Println(strings.Repeat("-", 60))
	for _, dep := range report.Dependents {
		indent := strings.Repeat("  ", dep.Depth-1)
		fmt.Printf("%s[depth %d | %s] secret %-5d %-30s (owner %d, project %d)\n",
			indent, dep.Depth, dep.RiskLevel,
			dep.SecretID, dep.SecretName,
			dep.OwnerID, dep.ProjectID)
	}
}

func init() {
	SecretCmd.AddCommand(blastRadiusCmd)
}
