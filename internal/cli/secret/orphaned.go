package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var orphanedProject uint

// orphanedRow mirrors a GET /projects/{id}/secrets/orphaned entry (snake_case DTO).
type orphanedRow struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification"`
	OwnerID        uint   `json:"owner_id"`
}

var orphanedCmd = &cobra.Command{
	Use:   "orphaned",
	Short: "List secrets whose owner is no longer a live user",
	Long: `Show a project's secrets whose owner has been deleted (offboarding hygiene). Each is
left without an accountable owner — re-assign one with 'keyorix secret transfer-ownership'.
Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if orphanedProject == 0 {
			return fmt.Errorf("--project is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchOrphaned(context.Background(), c, orphanedProject)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No orphaned secrets.")
			return nil
		}
		fmt.Printf("%-8s %-24s %-12s %-14s %s\n", "ID", "NAME", "TYPE", "CLASS", "EX-OWNER")
		for _, r := range rows {
			fmt.Printf("%-8d %-24s %-12s %-14s %d\n", r.ID, r.Name, r.Type, r.Classification, r.OwnerID)
		}
		return nil
	},
}

// fetchOrphaned GETs the project's orphaned secrets (split out for httptest tests).
func fetchOrphaned(ctx context.Context, c *common.RemoteClient, projectID uint) ([]orphanedRow, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/orphaned"
	var body struct {
		Orphaned []orphanedRow `json:"orphaned"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Orphaned, nil
}

func init() {
	orphanedCmd.Flags().UintVar(&orphanedProject, "project", 0, "Project ID (required)")
	SecretCmd.AddCommand(orphanedCmd)
}
