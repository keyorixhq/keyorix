// machine_hygiene_audit.go — `keyorix-next machine token-hygiene` and
// `keyorix-next machine audit`: deployment-wide, admin-only reports.
package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var machineTokenHygieneDays int

var machineTokenHygieneCmd = &cobra.Command{
	Use:   "token-hygiene",
	Short: "List stale or expired-but-active machine tokens across all identities (admin)",
	Long: `Show the deployment-wide machine-identity credentials that should probably be
revoked: ones that have expired but were never revoked, and ones unused for a long
window (non-human token sprawl). Requires global audit.read. Never prints a secret.`,
	SilenceUsage: true,
	RunE:         runMachineTokenHygiene,
}

var machineAuditFormat string

var machineAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Print a machine identity audit report (admin)",
	Long: `Generate a deployment-wide audit report of all machine identities.
Each row shows the identity's credential count, last-used timestamp,
whether it is stale (no activity > 30 days), and its revocation status.

Requires global audit.read permission.`,
	SilenceUsage: true,
	RunE:         runMachineAudit,
}

func init() {
	machineTokenHygieneCmd.Flags().IntVar(&machineTokenHygieneDays, "days", 0, "Staleness window in days (default server-side: 90, cap 3650)")
	machineAuditCmd.Flags().StringVar(&machineAuditFormat, "format", "json", "Output format: json or csv")
	machineCmd.AddCommand(machineTokenHygieneCmd, machineAuditCmd)
}

func runMachineTokenHygiene(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	var params *apiclient.MachineTokenHygieneParams
	if machineTokenHygieneDays > 0 {
		params = &apiclient.MachineTokenHygieneParams{Days: &machineTokenHygieneDays}
	}
	resp, err := client.MachineTokenHygieneWithResponse(context.Background(), params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("machine token hygiene failed: HTTP %d", resp.StatusCode())
	}
	var rows []apiclient.MachineTokenHygieneRow
	if resp.JSON200 != nil && resp.JSON200.Data != nil && resp.JSON200.Data.Tokens != nil {
		rows = *resp.JSON200.Data.Tokens
	}
	if len(rows) == 0 {
		fmt.Println("No stale or expired machine tokens.")
		return nil
	}
	fmt.Printf("%-5s %-22s %-16s %-8s %-8s %s\n", "ID", "NAME", "PREFIX", "MACHINE", "FLAGS", "LAST USED")
	for _, r := range rows {
		last := derefStr(r.LastUsedAt)
		if last == "" {
			last = "never"
		}
		fmt.Printf("%-5d %-22s %-16s %-8d %-8s %s\n", derefInt(r.Id), cliout.SanitizeForTerminal(derefStr(r.Name)), derefStr(r.TokenPrefix)+"…", derefInt(r.MachineIdentityId), machineHygieneFlagLabel(r), last)
	}
	return nil
}

func machineHygieneFlagLabel(r apiclient.MachineTokenHygieneRow) string {
	expired := r.Expired != nil && *r.Expired
	stale := r.Stale != nil && *r.Stale
	switch {
	case expired && stale:
		return "exp,stale"
	case expired:
		return "expired"
	default:
		return "stale"
	}
}

func runMachineAudit(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetMachineAuditReportWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("failed to fetch machine audit report: %w", err)
	}
	if resp.StatusCode() != 200 || resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("failed to fetch machine audit report: HTTP %d", resp.StatusCode())
	}
	report := *resp.JSON200.Data
	switch machineAuditFormat {
	case "csv":
		return printMachineAuditCSV(report)
	default:
		return printMachineAuditJSON(report)
	}
}

func printMachineAuditJSON(report apiclient.MachineAuditReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func printMachineAuditCSV(report apiclient.MachineAuditReport) error {
	cw := csv.NewWriter(os.Stdout)
	defer cw.Flush()
	if err := cw.Write([]string{
		"machine_id", "name", "description",
		"credential_count", "last_used_at",
		"is_stale", "is_revoked", "created_at",
	}); err != nil {
		return err
	}
	if report.Machines == nil {
		return cw.Error()
	}
	for _, m := range *report.Machines {
		lastUsed := ""
		if m.LastUsedAt != nil {
			lastUsed = m.LastUsedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		createdAt := ""
		if m.CreatedAt != nil {
			createdAt = m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		if err := cw.Write([]string{
			fmt.Sprintf("%d", derefInt(m.MachineId)),
			csvSafe(derefStr(m.Name)),
			csvSafe(derefStr(m.Description)),
			fmt.Sprintf("%d", derefInt(m.CredentialCount)),
			lastUsed,
			fmt.Sprintf("%v", derefBool(m.IsStale)),
			fmt.Sprintf("%v", derefBool(m.IsRevoked)),
			createdAt,
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

// csvSafe neutralizes a leading =/+/-/@/tab/CR (CSV/Excel formula injection) in
// attacker-controlled free text before it goes into a CSV cell, matching the old
// CLI's internal/cli/common.CSVSafe exactly.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}
