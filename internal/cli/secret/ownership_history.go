package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var ownershipHistoryID uint

// ownershipRecord mirrors a GET /secrets/{id}/ownership-history entry.
type ownershipRecord struct {
	EventID     uint   `json:"event_id"`
	FromID      uint   `json:"from_id"`
	ToID        uint   `json:"to_id"`
	ChangedBy   uint   `json:"changed_by"`
	ChangedAt   string `json:"changed_at"`
	Description string `json:"description"`
}

var ownershipHistoryCmd = &cobra.Command{
	Use:   "ownership-history",
	Short: "Show a secret's ownership-transfer chain",
	Long: `List all ownership transfers for a secret in chronological order. Each record
shows who the secret was transferred from, who it was transferred to, who performed
the transfer, and when. Requires secrets.read at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if ownershipHistoryID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		records, err := fetchOwnershipHistory(context.Background(), c, ownershipHistoryID)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			fmt.Println("No ownership transfers recorded.")
			return nil
		}
		fmt.Printf("%-10s %-10s %-10s %-10s %s\n", "EVENT ID", "FROM", "TO", "BY", "TIME")
		for _, r := range records {
			fmt.Printf("%-10d %-10d %-10d %-10d %s\n",
				r.EventID, r.FromID, r.ToID, r.ChangedBy, r.ChangedAt)
		}
		return nil
	},
}

// fetchOwnershipHistory GETs the ownership-transfer chain (split out for httptest tests).
func fetchOwnershipHistory(ctx context.Context, c *common.RemoteClient, id uint) ([]ownershipRecord, error) {
	var body struct {
		OwnershipHistory []ownershipRecord `json:"ownership_history"`
	}
	if err := c.Get(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/ownership-history", &body); err != nil {
		return nil, err
	}
	return body.OwnershipHistory, nil
}

func init() {
	ownershipHistoryCmd.Flags().UintVar(&ownershipHistoryID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(ownershipHistoryCmd)
}
