package pat

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var hygieneDays int

// hygieneRow mirrors a GET /pat-hygiene token entry (safe DTO — no token hash).
type hygieneRow struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	TokenPrefix string `json:"token_prefix"`
	UserID      uint   `json:"user_id"`
	ExpiresAt   string `json:"expires_at"`
	LastUsedAt  string `json:"last_used_at"`
	Expired     bool   `json:"expired"`
	Stale       bool   `json:"stale"`
}

var hygieneCmd = &cobra.Command{
	Use:   "hygiene",
	Short: "List stale or expired-but-active tokens across all users (admin)",
	Long: `Show the deployment-wide personal access tokens that should probably be revoked:
ones that have expired but were never revoked, and ones unused for a long window
(token sprawl). Requires global system.read. Never prints a token's secret.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		rows, err := fetchPATHygiene(context.Background(), c, hygieneDays)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No stale or expired tokens.")
			return nil
		}
		fmt.Printf("%-5s %-22s %-14s %-7s %-8s %s\n", "ID", "NAME", "PREFIX", "USER", "FLAGS", "LAST USED")
		for _, r := range rows {
			flags := flagLabel(r)
			last := r.LastUsedAt
			if last == "" {
				last = "never"
			}
			fmt.Printf("%-5d %-22s %-14s %-7d %-8s %s\n", r.ID, r.Name, r.TokenPrefix+"…", r.UserID, flags, last)
		}
		return nil
	},
}

func flagLabel(r hygieneRow) string {
	switch {
	case r.Expired && r.Stale:
		return "exp,stale"
	case r.Expired:
		return "expired"
	default:
		return "stale"
	}
}

// fetchPATHygiene GETs the hygiene list (split out for httptest tests). days <= 0 lets
// the server default (90).
func fetchPATHygiene(ctx context.Context, c *common.RemoteClient, days int) ([]hygieneRow, error) {
	path := "/api/v1/pat-hygiene"
	if days > 0 {
		path += "?days=" + strconv.Itoa(days)
	}
	var body struct {
		Tokens []hygieneRow `json:"tokens"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Tokens, nil
}

func init() {
	hygieneCmd.Flags().IntVar(&hygieneDays, "days", 0, "Staleness window in days (default server-side: 90, cap 3650)")
	PATCmd.AddCommand(hygieneCmd)
}
