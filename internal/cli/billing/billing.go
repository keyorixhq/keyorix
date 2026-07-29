// Package billing provides the `keyorix billing` CLI command and its `report`
// subcommand, which prints a per-project FinOps billing report.
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

// NewBillingCmd returns the top-level `keyorix billing` command with its
// subcommands.
func NewBillingCmd() *cobra.Command {
	billingCmd := &cobra.Command{
		Use:   "billing",
		Short: "FinOps billing and usage reports (requires billing license feature)",
	}
	billingCmd.AddCommand(newReportCmd())
	return billingCmd
}

var (
	flagFrom      string
	flagTo        string
	flagProjectID string
	flagFormat    string
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a per-project billing report for a date range",
		Long: `Generate a per-project billing report showing secret counts, reads,
writes, rotations, unique human users, and machine reads for the
specified date window. Requires the "billing" license feature.`,
		RunE: runReport,
	}
	cmd.Flags().StringVar(&flagFrom, "from", "", "Start of billing window, RFC3339 (e.g. 2026-01-01T00:00:00Z) — required")
	cmd.Flags().StringVar(&flagTo, "to", "", "End of billing window, RFC3339 (e.g. 2026-02-01T00:00:00Z) — required")
	cmd.Flags().StringVar(&flagProjectID, "project-id", "", "Comma-separated project IDs to include (omit for all)")
	cmd.Flags().StringVar(&flagFormat, "format", "table", "Output format: table or json")
	if err := cmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
	return cmd
}

func runReport(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	// Validate from/to before making any calls
	from, err := time.Parse(time.RFC3339, flagFrom)
	if err != nil {
		return fmt.Errorf("invalid --from value %q: must be RFC3339 (e.g. 2026-01-01T00:00:00Z)", flagFrom)
	}
	to, err := time.Parse(time.RFC3339, flagTo)
	if err != nil {
		return fmt.Errorf("invalid --to value %q: must be RFC3339 (e.g. 2026-02-01T00:00:00Z)", flagTo)
	}

	// Remote mode: proxy to GET /api/v1/admin/billing/report
	if rc, ok := common.NewRemoteClient(); ok {
		return runReportRemote(ctx, rc, from, to)
	}

	// Local/embedded mode: query via core service directly
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	svc := core.NewKeyorixCore(st)

	projectIDs, err := parseProjectIDs(flagProjectID)
	if err != nil {
		return err
	}

	report, err := svc.GenerateBillingReport(ctx, from, to, projectIDs)
	if err != nil {
		return fmt.Errorf("failed to generate billing report: %w", err)
	}
	return printBillingReport(report)
}

// runReportRemote proxies the billing report fetch to the connected server.
func runReportRemote(ctx context.Context, rc *common.RemoteClient, from, to time.Time) error {
	params := url.Values{}
	params.Set("from", from.UTC().Format(time.RFC3339))
	params.Set("to", to.UTC().Format(time.RFC3339))
	if flagProjectID != "" {
		params.Set("project_id", flagProjectID)
	}
	path := "/api/v1/admin/billing/report?" + params.Encode()

	var report storage.BillingReport
	if err := rc.Get(ctx, path, &report); err != nil {
		return fmt.Errorf("failed to fetch billing report: %w", err)
	}
	return printBillingReport(&report)
}

func printBillingReport(report *storage.BillingReport) error {
	if flagFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Sort projects by name for stable output
	sort.Slice(report.Projects, func(i, j int) bool {
		if report.Projects[i].ProjectName != report.Projects[j].ProjectName {
			return report.Projects[i].ProjectName < report.Projects[j].ProjectName
		}
		return report.Projects[i].ProjectID < report.Projects[j].ProjectID
	})

	fmt.Printf("Billing report %s – %s (generated %s)\n\n",
		report.From.Format("2006-01-02"),
		report.To.Format("2006-01-02"),
		report.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
	)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "PROJECT\tSECRETS\tREADS\tWRITES\tROTATIONS\tUNIQUE USERS\tMACHINE READS"); err != nil {
		return err
	}
	for _, p := range report.Projects {
		name := p.ProjectName
		if name == "" {
			name = fmt.Sprintf("(project %d)", p.ProjectID)
		}
		if _, err := fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			name, p.SecretCount, p.SecretReads, p.SecretWrites,
			p.SecretRotations, p.UniqueUsers, p.MachineReads); err != nil {
			return err
		}
	}
	if len(report.Projects) == 0 {
		if _, err := fmt.Fprintln(w, "(no data)"); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Print totals line
	t := report.Totals
	fmt.Printf("\nTotals (%d project(s)): %d secrets  %d reads  %d writes  %d rotations  %d unique users  %d machine reads\n",
		t.Projects, t.SecretCount, t.SecretReads, t.SecretWrites,
		t.SecretRotations, t.UniqueUsers, t.MachineReads,
	)
	return nil
}

// parseProjectIDs parses a comma-separated string of uint project IDs.
// Returns nil when the string is empty (all projects).
func parseProjectIDs(s string) ([]uint, error) {
	if s == "" {
		return nil, nil
	}
	var ids []uint
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid project ID %q: %w", part, err)
		}
		ids = append(ids, uint(n))
	}
	return ids, nil
}
