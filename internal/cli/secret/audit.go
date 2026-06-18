package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	auditID    uint
	auditLimit int
)

// auditRow mirrors a GET /secrets/{id}/audit entry (snake_case DTO). The diff is
// rendered as a presence marker only — it never carries a plaintext value.
type auditRow struct {
	EventType   string `json:"event_type"`
	Timestamp   string `json:"timestamp"`
	ActorType   string `json:"actor_type"`
	UserID      *uint  `json:"user_id"`
	Description string `json:"description"`
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show a secret's lifecycle events (created/rotated/suspended/shared/…)",
	Long: `List the audit trail for a secret: what happened to it and when (created, rotated,
rolled-back, suspended/resumed, shared, owner-transferred, reclassified), newest first.
Requires secrets.read at the secret's scope. Never prints a plaintext value.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if auditID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchAuditTrail(context.Background(), c, auditID, auditLimit)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No audit events.")
			return nil
		}
		fmt.Printf("%-26s %-24s %-8s %s\n", "EVENT", "TIME", "ACTOR", "DESCRIPTION")
		for _, r := range rows {
			fmt.Printf("%-26s %-24s %-8s %s\n", r.EventType, r.Timestamp, r.ActorType, r.Description)
		}
		return nil
	},
}

// fetchAuditTrail GETs the secret's lifecycle events (split out for httptest tests).
// limit <= 0 lets the server default (50).
func fetchAuditTrail(ctx context.Context, c *common.RemoteClient, id uint, limit int) ([]auditRow, error) {
	path := "/api/v1/secrets/" + strconv.Itoa(int(id)) + "/audit"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var body struct {
		Audit []auditRow `json:"audit"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Audit, nil
}

func init() {
	auditCmd.Flags().UintVar(&auditID, "id", 0, "Secret ID (required)")
	auditCmd.Flags().IntVar(&auditLimit, "limit", 0, "Max events to show (default server-side: 50, cap 500)")
	SecretCmd.AddCommand(auditCmd)
}
