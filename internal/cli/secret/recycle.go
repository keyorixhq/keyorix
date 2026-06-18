package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	trashProject uint
	trashLimit   int
	restoreID    uint
)

// trashRow mirrors a GET /projects/{id}/secrets/deleted entry (snake_case DTO).
type trashRow struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification"`
	DeletedAt      string `json:"deleted_at"`
}

var trashCmd = &cobra.Command{
	Use:   "trash",
	Short: "List a project's soft-deleted (restorable) secrets",
	Long: `Show the recycle bin for a project: secrets that were deleted but are still
restorable (until the purge job reaps them), newest-deleted first. Use the ID with
'keyorix secret restore --id <id>'. Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if trashProject == 0 {
			return fmt.Errorf("--project is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchTrash(context.Background(), c, trashProject, trashLimit)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("Recycle bin is empty.")
			return nil
		}
		fmt.Printf("%-8s %-24s %-12s %-14s %s\n", "ID", "NAME", "TYPE", "CLASS", "DELETED")
		for _, r := range rows {
			fmt.Printf("%-8d %-24s %-12s %-14s %s\n", r.ID, r.Name, r.Type, r.Classification, r.DeletedAt)
		}
		return nil
	},
}

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a soft-deleted secret",
	Long: `Restore a soft-deleted secret by clearing its deletion, returning it to the live
list. Find restorable secrets with 'keyorix secret trash --project <id>'. Requires
secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if restoreID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if err := restoreSecret(context.Background(), c, restoreID); err != nil {
			return err
		}
		fmt.Printf("✅ Secret %d restored.\n", restoreID)
		return nil
	},
}

// fetchTrash GETs the project's recycle bin (split out for httptest tests).
// limit <= 0 lets the server default (100).
func fetchTrash(ctx context.Context, c *common.RemoteClient, projectID uint, limit int) ([]trashRow, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/deleted"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var body struct {
		Deleted []trashRow `json:"deleted"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Deleted, nil
}

// restoreSecret POSTs the restore (split out for httptest tests). The endpoint
// returns {"id":…,"restored":true}; we decode it so the envelope is consumed.
func restoreSecret(ctx context.Context, c *common.RemoteClient, id uint) error {
	var out struct {
		ID       uint `json:"id"`
		Restored bool `json:"restored"`
	}
	return c.Post(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/restore", struct{}{}, &out)
}

func init() {
	trashCmd.Flags().UintVar(&trashProject, "project", 0, "Project ID (required)")
	trashCmd.Flags().IntVar(&trashLimit, "limit", 0, "Max entries to show (default server-side: 100, cap 500)")
	restoreCmd.Flags().UintVar(&restoreID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(trashCmd)
	SecretCmd.AddCommand(restoreCmd)
}
