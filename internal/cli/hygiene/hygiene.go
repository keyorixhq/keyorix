// Package hygiene is the top-level `keyorix hygiene` command: the deployment-wide
// secret-hygiene rollup — install-wide totals of every project's cleanup signals plus
// a per-project breakdown of the projects that carry debt. The per-project view is
// `keyorix project hygiene <id>`; this is the admin's bird's-eye counterpart.
package hygiene

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	unusedDays   int
	expiringDays int
	staleDays    int
)

// counts mirrors the per-project hygiene tally (counts only).
type counts struct {
	OrphanedSecrets        int `json:"orphaned_secrets"`
	UnusedSecrets          int `json:"unused_secrets"`
	ExpiringSecrets        int `json:"expiring_secrets"`
	StaleMachineIdentities int `json:"stale_machine_identities"`
	RotationOverdue        int `json:"rotation_overdue"`
}

// projectBreakdown is one project's counts, identified.
type projectBreakdown struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	counts
}

// rollup mirrors the GET /hygiene response.
type rollup struct {
	Totals   counts             `json:"totals"`
	Projects []projectBreakdown `json:"projects"`
}

// HygieneCmd is the top-level deployment-wide hygiene command.
var HygieneCmd = &cobra.Command{
	Use:   "hygiene",
	Short: "Deployment-wide secret-hygiene rollup across all projects (admin)",
	Long: `Summarize every project's outstanding cleanup signals in one call: secrets whose
owner departed, secrets unused for a long window, secrets expiring/expired, stale
machine identities, and secrets overdue for rotation. Shows install-wide totals plus a
per-project breakdown of the projects that carry debt. Requires global system.read.
Counts only — never secret names or values.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		r, err := fetchDeploymentHygiene(context.Background(), c, unusedDays, expiringDays, staleDays)
		if err != nil {
			return err
		}
		printRollup(r)
		return nil
	},
}

func printRollup(r *rollup) {
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
		// #G69: ProjectName is attacker-controlled free text — a crafted
		// project name must not be able to embed terminal escape sequences
		// that overwrite or hide rows in this deployment-wide rollup.
		fmt.Printf("%-6d %-22s %-9d %-7d %-9d %-9d %d\n",
			p.ProjectID, common.SanitizeForTerminal(p.ProjectName), p.OrphanedSecrets, p.UnusedSecrets,
			p.ExpiringSecrets, p.StaleMachineIdentities, p.RotationOverdue)
	}
}

// fetchDeploymentHygiene GETs the rollup (split out for httptest tests). Non-positive
// windows are omitted so the server applies its defaults.
func fetchDeploymentHygiene(ctx context.Context, c *common.RemoteClient, unused, expiring, stale int) (*rollup, error) {
	path := "/api/v1/hygiene"
	sep := "?"
	add := func(key string, val int) {
		if val > 0 {
			path += sep + key + "=" + fmt.Sprintf("%d", val)
			sep = "&"
		}
	}
	add("unused_days", unused)
	add("expiring_days", expiring)
	add("stale_days", stale)

	var out rollup
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func init() {
	HygieneCmd.Flags().IntVar(&unusedDays, "unused-days", 0, "Unused-secret window in days (default server-side: 90)")
	HygieneCmd.Flags().IntVar(&expiringDays, "expiring-days", 0, "Expiring-secret window in days (default server-side: 30)")
	HygieneCmd.Flags().IntVar(&staleDays, "stale-days", 0, "Stale-machine-identity window in days (default server-side: 90)")
}
