package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	expiringProject uint
	expiringDays    int
)

// expiringRow mirrors a GET /projects/{id}/secrets/expiring entry (snake_case DTO).
type expiringRow struct {
	ID            uint   `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	EnvironmentID uint   `json:"environment_id"`
	Expiration    string `json:"expiration"`
	Expired       bool   `json:"expired"`
}

var expiringCmd = &cobra.Command{
	Use:   "expiring",
	Short: "List a project's secrets expiring (or already expired) within a window",
	Long: `Show a project's secrets expiring soon (or already expired), soonest-first, so you can
renew or rotate them before they lapse. Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if expiringProject == 0 {
			return fmt.Errorf("--project is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchExpiring(context.Background(), c, expiringProject, expiringDays)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No expiring secrets.")
			return nil
		}
		fmt.Printf("%-8s %-24s %-12s %-10s %s\n", "ID", "NAME", "TYPE", "STATE", "EXPIRES")
		for _, r := range rows {
			state := "expiring"
			if r.Expired {
				state = "EXPIRED"
			}
			fmt.Printf("%-8d %-24s %-12s %-10s %s\n", r.ID, r.Name, r.Type, state, r.Expiration)
		}
		return nil
	},
}

// fetchExpiring GETs the project's expiring secrets (split out for httptest tests).
// days <= 0 lets the server default (30).
func fetchExpiring(ctx context.Context, c *common.RemoteClient, projectID uint, days int) ([]expiringRow, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/expiring"
	if days > 0 {
		path += "?days=" + strconv.Itoa(days)
	}
	var body struct {
		Expiring []expiringRow `json:"expiring"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Expiring, nil
}

func init() {
	expiringCmd.Flags().UintVar(&expiringProject, "project", 0, "Project ID (required)")
	expiringCmd.Flags().IntVar(&expiringDays, "days", 0, "Window in days (default server-side: 30, cap 3650)")
	SecretCmd.AddCommand(expiringCmd)
}
