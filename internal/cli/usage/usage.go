// Package usage provides the `keyorix usage` CLI command and its `show`
// subcommand, which prints a per-project secret usage report.
package usage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

// UsageCmd is the top-level `keyorix usage` command.
var UsageCmd = &cobra.Command{
	Use:   "usage",
	Short: "View usage and activity reports",
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show per-project secret usage for a time window",
	RunE:  runShow,
}

var (
	flagDays      int
	flagProjectID uint
	flagFormat    string
)

func init() {
	showCmd.Flags().IntVar(&flagDays, "days", 30, "Reporting window in days (1-365)")
	showCmd.Flags().UintVar(&flagProjectID, "project-id", 0, "Scope to a single project (0 = all)")
	showCmd.Flags().StringVar(&flagFormat, "format", "table", "Output format: table or json")
	UsageCmd.AddCommand(showCmd)
}

func runShow(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	// Remote mode: proxy to GET /api/v1/admin/usage
	if rc, ok := common.NewRemoteClient(); ok {
		return runShowRemote(ctx, rc)
	}

	// Local/embedded mode: query the database directly
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	svc := core.NewKeyorixCore(st)

	var projectID *uint
	if flagProjectID != 0 {
		id := flagProjectID
		projectID = &id
	}

	report, err := svc.GetUsageReport(ctx, flagDays, projectID)
	if err != nil {
		return fmt.Errorf("failed to generate usage report: %w", err)
	}

	return printReport(report)
}

// runShowRemote proxies the report fetch to the connected server.
func runShowRemote(ctx context.Context, rc *common.RemoteClient) error {
	path := fmt.Sprintf("/api/v1/admin/usage?days=%d", flagDays)
	if flagProjectID != 0 {
		path += fmt.Sprintf("&project_id=%d", flagProjectID)
	}

	var report storage.UsageReport
	if err := rc.Get(ctx, path, &report); err != nil {
		return fmt.Errorf("failed to fetch usage report: %w", err)
	}
	return printReport(&report)
}

func printReport(report *storage.UsageReport) error {
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

	fmt.Printf("Usage report — last %d days (generated %s)\n\n",
		report.WindowDays, report.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "PROJECT\tSECRETS\tREADS\tUNIQUE READERS"); err != nil {
		return err
	}
	for _, p := range report.Projects {
		// #G69: ProjectName is attacker-controlled free text — an operator
		// or self-chosen display name must not be able to embed terminal
		// escape sequences that overwrite or hide rows in this report.
		name := common.SanitizeForTerminal(p.ProjectName)
		if name == "" {
			name = fmt.Sprintf("(project %d)", p.ProjectID)
		}
		if _, err := fmt.Fprintf(w, "%s\t%d\t%d\t%d\n", name, p.SecretCount, p.ReadsInWindow, p.UniqueReaders); err != nil {
			return err
		}
	}
	if len(report.Projects) == 0 {
		if _, err := fmt.Fprintln(w, "(no data)"); err != nil {
			return err
		}
	}
	return w.Flush()
}
