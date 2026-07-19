// hygiene_trends.go — `keyorix compliance credential-trends` subcommand.
//
// Talks to GET /api/v1/compliance/credential-trends?days=30|60|90 and prints
// a per-day table of stale/expired PAT and stale machine-credential counts.
package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var credTrendDays int

// trendPoint mirrors core.HygieneTrendPoint for JSON decoding.
type trendPoint struct {
	Date          time.Time `json:"date"`
	StalePATs     int       `json:"stale_pats"`
	ExpiredPATs   int       `json:"expired_pats"`
	StaleMachines int       `json:"stale_machines"`
	TotalPATs     int       `json:"total_pats"`
	TotalMachines int       `json:"total_machines"`
}

type trendsReport struct {
	Days   int          `json:"days"`
	Points []trendPoint `json:"points"`
}

var credentialTrendsCmd = &cobra.Command{
	Use:          "credential-trends",
	Short:        "Show 30/60/90-day credential hygiene trends (stale/expired PATs, stale machine creds)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if credTrendDays != 30 && credTrendDays != 60 && credTrendDays != 90 {
			credTrendDays = 30
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var report trendsReport
		url := fmt.Sprintf("/api/v1/compliance/credential-trends?days=%d", credTrendDays)
		if err := c.Get(context.Background(), url, &report); err != nil {
			return err
		}
		fmt.Printf("Credential hygiene trends — last %d days\n\n", report.Days)
		fmt.Printf("%-12s  %10s  %12s  %14s  %10s  %14s\n",
			"Date", "StalePATs", "ExpiredPATs", "StaleMachines", "TotalPATs", "TotalMachines")
		fmt.Printf("%-12s  %10s  %12s  %14s  %10s  %14s\n",
			"------------", "----------", "------------", "--------------", "----------", "--------------")
		for _, p := range report.Points {
			fmt.Printf("%-12s  %10d  %12d  %14d  %10d  %14d\n",
				p.Date.UTC().Format("2006-01-02"),
				p.StalePATs,
				p.ExpiredPATs,
				p.StaleMachines,
				p.TotalPATs,
				p.TotalMachines,
			)
		}
		return nil
	},
}

func init() {
	credentialTrendsCmd.Flags().IntVar(&credTrendDays, "days", 30, "Trend window in days (30, 60, or 90)")
	ComplianceCmd.AddCommand(credentialTrendsCmd)
}
