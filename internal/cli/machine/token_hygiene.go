package machine

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var tokenHygieneDays int

// machineTokenHygieneRow mirrors a GET /machine-token-hygiene entry (safe DTO — no hash).
type machineTokenHygieneRow struct {
	ID                uint   `json:"id"`
	MachineIdentityID uint   `json:"machine_identity_id"`
	Name              string `json:"name"`
	TokenPrefix       string `json:"token_prefix"`
	LastUsedAt        string `json:"last_used_at"`
	Expired           bool   `json:"expired"`
	Stale             bool   `json:"stale"`
}

var tokenHygieneCmd = &cobra.Command{
	Use:   "token-hygiene",
	Short: "List stale or expired-but-active machine tokens across all identities (admin)",
	Long: `Show the deployment-wide machine-identity credentials that should probably be
revoked: ones that have expired but were never revoked, and ones unused for a long
window (non-human token sprawl). Requires global system.read. Never prints a secret.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchMachineTokenHygiene(context.Background(), c, tokenHygieneDays)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No stale or expired machine tokens.")
			return nil
		}
		fmt.Printf("%-5s %-22s %-16s %-8s %-8s %s\n", "ID", "NAME", "PREFIX", "MACHINE", "FLAGS", "LAST USED")
		for _, r := range rows {
			last := r.LastUsedAt
			if last == "" {
				last = "never"
			}
			fmt.Printf("%-5d %-22s %-16s %-8d %-8s %s\n", r.ID, r.Name, r.TokenPrefix+"…", r.MachineIdentityID, machineFlagLabel(r), last)
		}
		return nil
	},
}

func machineFlagLabel(r machineTokenHygieneRow) string {
	switch {
	case r.Expired && r.Stale:
		return "exp,stale"
	case r.Expired:
		return "expired"
	default:
		return "stale"
	}
}

// fetchMachineTokenHygiene GETs the hygiene list (split out for httptest tests).
// days <= 0 lets the server default (90).
func fetchMachineTokenHygiene(ctx context.Context, c *common.RemoteClient, days int) ([]machineTokenHygieneRow, error) {
	path := "/api/v1/machine-token-hygiene"
	if days > 0 {
		path += "?days=" + strconv.Itoa(days)
	}
	var body struct {
		Tokens []machineTokenHygieneRow `json:"tokens"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Tokens, nil
}

func init() {
	tokenHygieneCmd.Flags().IntVar(&tokenHygieneDays, "days", 0, "Staleness window in days (default server-side: 90, cap 3650)")
	MachineCmd.AddCommand(tokenHygieneCmd)
}
