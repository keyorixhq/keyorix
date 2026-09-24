// hygiene.go ports the top-level `keyorix hygiene` command (docs/cli-split-inventory.md
// §2.6, PR 8): the deployment-wide secret-hygiene rollup -- install-wide totals of every
// project's cleanup signals plus a per-project breakdown of the projects that carry debt.
// Same flags, output, and exit codes as the old CLI's internal/cli/hygiene package -- a
// pure transport port, not a behavior change.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var (
	hygieneUnusedDays   int
	hygieneExpiringDays int
	hygieneStaleDays    int
)

type hygieneCounts struct {
	OrphanedSecrets        int `json:"orphaned_secrets"`
	UnusedSecrets          int `json:"unused_secrets"`
	ExpiringSecrets        int `json:"expiring_secrets"`
	StaleMachineIdentities int `json:"stale_machine_identities"`
	RotationOverdue        int `json:"rotation_overdue"`
}

type hygieneProjectBreakdown struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	hygieneCounts
}

type hygieneRollup struct {
	Totals   hygieneCounts             `json:"totals"`
	Projects []hygieneProjectBreakdown `json:"projects"`
}

var hygieneCmd = &cobra.Command{
	Use:   "hygiene",
	Short: "Deployment-wide secret-hygiene rollup across all projects (admin)",
	Long: `Summarize every project's outstanding cleanup signals in one call: secrets whose
owner departed, secrets unused for a long window, secrets expiring/expired, stale
machine identities, and secrets overdue for rotation. Shows install-wide totals plus a
per-project breakdown of the projects that carry debt. Requires global system.read.
Counts only — never secret names or values.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		r, err := fetchDeploymentHygiene(ctx, client, hygieneUnusedDays, hygieneExpiringDays, hygieneStaleDays)
		if err != nil {
			return err
		}
		printHygieneRollup(r)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(hygieneCmd)
}

func printHygieneRollup(r *hygieneRollup) {
	fmt.Println("Deployment-wide hygiene totals:")
	fmt.Printf("  orphaned secrets         %d\n", r.Totals.OrphanedSecrets)
	fmt.Printf("  unused secrets           %d\n", r.Totals.UnusedSecrets)
	fmt.Printf("  expiring/expired secrets %d\n", r.Totals.ExpiringSecrets)
	fmt.Printf("  stale machine identities %d\n", r.Totals.StaleMachineIdentities)
	fmt.Printf("  rotation overdue         %d\n", r.Totals.RotationOverdue)

	if len(r.Projects) == 0 {
		fmt.Println("\nNo projects carry outstanding signals. ✅")
		return
	}
	fmt.Printf("\nProjects with debt (%d):\n", len(r.Projects))
	fmt.Printf("%-6s %-22s %-9s %-7s %-9s %-9s %s\n", "ID", "NAME", "ORPHANED", "UNUSED", "EXPIRING", "STALE-MI", "ROT-OVERDUE")
	for _, p := range r.Projects {
		fmt.Printf("%-6d %-22s %-9d %-7d %-9d %-9d %d\n",
			p.ProjectID, cliout.SanitizeForTerminal(p.ProjectName), p.OrphanedSecrets, p.UnusedSecrets,
			p.ExpiringSecrets, p.StaleMachineIdentities, p.RotationOverdue)
	}
}

// fetchDeploymentHygiene GETs the rollup. Non-positive windows are omitted so the server
// applies its defaults.
func fetchDeploymentHygiene(ctx context.Context, client *apiclient.ClientWithResponses, unused, expiring, stale int) (*hygieneRollup, error) {
	params := &apiclient.GetDeploymentHygieneParams{}
	if unused > 0 {
		params.UnusedDays = &unused
	}
	if expiring > 0 {
		params.ExpiringDays = &expiring
	}
	if stale > 0 {
		params.StaleDays = &stale
	}
	resp, err := client.GetDeploymentHygieneWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, apiError("get deployment hygiene", resp.StatusCode(), resp.Body)
	}
	out, err := decodeData[hygieneRollup](resp.Body)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func init() {
	hygieneCmd.Flags().IntVar(&hygieneUnusedDays, "unused-days", 0, "Unused-secret window in days (default server-side: 90)")
	hygieneCmd.Flags().IntVar(&hygieneExpiringDays, "expiring-days", 0, "Expiring-secret window in days (default server-side: 30)")
	hygieneCmd.Flags().IntVar(&hygieneStaleDays, "stale-days", 0, "Stale-machine-identity window in days (default server-side: 90)")
}
