package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	bulkRenameProject uint
	bulkRenameApply   bool
	bulkRenamePairs   []string
)

// bulkRenameEntry is one requested rename in the POST body (snake_case DTO).
type bulkRenameEntry struct {
	ID      uint   `json:"id"`
	NewName string `json:"new_name"`
}

// bulkRenameOutcome mirrors one outcome in the bulk-rename report.
type bulkRenameOutcome struct {
	ID      uint   `json:"id"`
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
}

// bulkRenameReport mirrors the report envelope's data object.
type bulkRenameReport struct {
	DryRun   bool                `json:"dry_run"`
	Renamed  int                 `json:"renamed"`
	Skipped  int                 `json:"skipped"`
	Outcomes []bulkRenameOutcome `json:"outcomes"`
}

var bulkRenameCmd = &cobra.Command{
	Use:   "bulk-rename",
	Short: "Rename secrets toward naming-policy conformance",
	Long: `Rename one or more secrets in a project in a single call — the remediation for the
secrets that "secret name-conformance" lists as violating the current naming policy.

Each new name must itself satisfy the policy (you can only rename TOWARD conformance) and
must not collide with another secret in the same environment; any entry failing a check
is skipped with a reason while the rest proceed.

Specify renames as --rename <id>=<new-name> (repeatable). By default this is a DRY RUN
that only reports what would change; pass --apply to actually rename. Requires
secrets.write at the project scope.

  keyorix secret bulk-rename --project 7 --rename 12=APP_DB_PASSWORD --rename 15=APP_API_KEY
  keyorix secret bulk-rename --project 7 --rename 12=APP_DB_PASSWORD --apply`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if bulkRenameProject == 0 {
			return fmt.Errorf("--project is required")
		}
		if len(bulkRenamePairs) == 0 {
			return fmt.Errorf("at least one --rename <id>=<new-name> is required")
		}
		entries, err := parseRenamePairs(bulkRenamePairs)
		if err != nil {
			return err
		}

		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		report, err := postBulkRename(context.Background(), c, bulkRenameProject, entries, !bulkRenameApply)
		if err != nil {
			return err
		}

		if report.DryRun {
			fmt.Printf("Dry run — no changes made. Pass --apply to rename.\n\n")
		}
		fmt.Printf("%-8s %-24s %-24s %-14s %s\n", "ID", "OLD NAME", "NEW NAME", "STATUS", "REASON")
		for _, o := range report.Outcomes {
			fmt.Printf("%-8d %-24s %-24s %-14s %s\n", o.ID, o.OldName, o.NewName, o.Status, o.Reason)
		}
		verb := "renamed"
		if report.DryRun {
			verb = "would be renamed"
		}
		fmt.Printf("\n%d %s, %d skipped.\n", report.Renamed, verb, report.Skipped)
		return nil
	},
}

// parseRenamePairs turns ["12=NAME","15=OTHER"] into rename entries, splitting on the
// FIRST '=' so a new name may itself contain '='.
func parseRenamePairs(pairs []string) ([]bulkRenameEntry, error) {
	entries := make([]bulkRenameEntry, 0, len(pairs))
	for _, p := range pairs {
		idStr, name, found := strings.Cut(p, "=")
		if !found {
			return nil, fmt.Errorf("invalid --rename %q: expected <id>=<new-name>", p)
		}
		id, err := strconv.ParseUint(strings.TrimSpace(idStr), 10, 32)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid --rename %q: %q is not a valid secret ID", p, idStr)
		}
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("invalid --rename %q: new name is empty", p)
		}
		entries = append(entries, bulkRenameEntry{ID: uint(id), NewName: name})
	}
	return entries, nil
}

// postBulkRename POSTs the rename request (split out for httptest tests).
func postBulkRename(ctx context.Context, c *common.RemoteClient, projectID uint, entries []bulkRenameEntry, dryRun bool) (bulkRenameReport, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/bulk-rename"
	body := map[string]interface{}{"renames": entries, "dry_run": dryRun}
	var report bulkRenameReport
	if err := c.Post(ctx, path, body, &report); err != nil {
		return bulkRenameReport{}, err
	}
	return report, nil
}

func init() {
	bulkRenameCmd.Flags().UintVar(&bulkRenameProject, "project", 0, "Project ID (required)")
	bulkRenameCmd.Flags().StringArrayVar(&bulkRenamePairs, "rename", nil, "Rename as <id>=<new-name> (repeatable)")
	bulkRenameCmd.Flags().BoolVar(&bulkRenameApply, "apply", false, "Actually rename (default is a dry run)")
	SecretCmd.AddCommand(bulkRenameCmd)
}
