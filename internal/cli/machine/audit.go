// audit.go — `keyorix machine audit` command: machine identity audit report.
//
// Prints a deployment-wide audit report of all machine identities, including
// credential counts, last-used timestamps, stale status, and revocation status.
// Requires a remote server connection (audit.read permission).
package machine

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var auditFormat string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Print a machine identity audit report (admin)",
	Long: `Generate a deployment-wide audit report of all machine identities.
Each row shows the identity's credential count, last-used timestamp,
whether it is stale (no activity > 30 days), and its revocation status.

Requires global audit.read permission. Run against a connected server.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		report, err := fetchMachineAuditReport(context.Background(), c)
		if err != nil {
			return err
		}
		switch auditFormat {
		case "csv":
			return printMachineAuditCSV(report)
		default:
			return printMachineAuditJSON(report)
		}
	},
}

// fetchMachineAuditReport GETs the audit report from the server.
func fetchMachineAuditReport(ctx context.Context, c *common.RemoteClient) (*core.MachineAuditReport, error) {
	var report core.MachineAuditReport
	if err := c.Get(ctx, "/api/v1/machine-identities/audit", &report); err != nil {
		return nil, fmt.Errorf("failed to fetch machine audit report: %w", err)
	}
	return &report, nil
}

// printMachineAuditJSON prints the report as indented JSON.
func printMachineAuditJSON(report *core.MachineAuditReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// printMachineAuditCSV prints the report in CSV format to stdout.
func printMachineAuditCSV(report *core.MachineAuditReport) error {
	cw := csv.NewWriter(os.Stdout)
	defer cw.Flush()
	if err := cw.Write([]string{
		"machine_id", "name", "description",
		"credential_count", "last_used_at",
		"is_stale", "is_revoked", "created_at",
	}); err != nil {
		return err
	}
	for _, m := range report.Machines {
		lastUsed := ""
		if m.LastUsedAt != nil {
			lastUsed = m.LastUsedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		if err := cw.Write([]string{
			fmt.Sprintf("%d", m.MachineID),
			m.Name,
			m.Description,
			fmt.Sprintf("%d", m.CredentialCount),
			lastUsed,
			fmt.Sprintf("%v", m.IsStale),
			fmt.Sprintf("%v", m.IsRevoked),
			m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func init() {
	auditCmd.Flags().StringVar(&auditFormat, "format", "json", "Output format: json or csv")
	MachineCmd.AddCommand(auditCmd)
}
