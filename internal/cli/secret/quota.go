package secret

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// quotaReportRow mirrors a GET /secrets/quota-report entry (snake_case DTO).
type quotaReportRow struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	ReadCount  int    `json:"read_count"`
	MaxReads   int    `json:"max_reads"`
	UsagePct   int    `json:"usage_pct"`
	Status     string `json:"status"`
}

var quotaReportCmd = &cobra.Command{
	Use:   "quota-report",
	Short: "Show secrets approaching or at their MaxReads quota",
	Long: `List all secrets with a MaxReads cap configured, showing current read count,
quota percentage, and status (ok / warning / critical / exhausted). Requires secrets.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchQuotaReport(context.Background(), c)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No secrets with a read quota configured.")
			return nil
		}
		fmt.Printf("%-8s %-28s %10s %10s %8s %s\n", "ID", "NAME", "READ_COUNT", "MAX_READS", "USAGE%", "STATUS")
		for _, r := range rows {
			fmt.Printf("%-8d %-28s %10d %10d %7d%% %s\n",
				r.SecretID, r.SecretName, r.ReadCount, r.MaxReads, r.UsagePct, r.Status)
		}
		return nil
	},
}

// fetchQuotaReport calls GET /api/v1/secrets/quota-report.
func fetchQuotaReport(ctx context.Context, c *common.RemoteClient) ([]quotaReportRow, error) {
	var body struct {
		Secrets []quotaReportRow `json:"secrets"`
	}
	if err := c.Get(ctx, "/api/v1/secrets/quota-report", &body); err != nil {
		return nil, err
	}
	return body.Secrets, nil
}

func init() {
	SecretCmd.AddCommand(quotaReportCmd)
}
