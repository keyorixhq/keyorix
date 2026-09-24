package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── audit-logs ──────────────────────────────────────────────────────────────────

var (
	rbacAuditLimit  int
	rbacAuditOffset int
)

var rbacAuditLogsCmd = &cobra.Command{
	Use:   "audit-logs",
	Short: "View RBAC audit logs",
	Long:  "View audit logs for RBAC operations (role assignments, removals, permission grants).",
	RunE:  runRBACAuditLogs,
}

func init() {
	rbacAuditLogsCmd.Flags().IntVar(&rbacAuditLimit, "limit", 50, "Maximum number of logs to retrieve")
	rbacAuditLogsCmd.Flags().IntVar(&rbacAuditOffset, "offset", 0, "Number of logs to skip")
	rbacCmd.AddCommand(rbacAuditLogsCmd)
}

func runRBACAuditLogs(cmd *cobra.Command, args []string) error {
	if rbacAuditLimit < 1 {
		rbacAuditLimit = 50
	}
	page := (rbacAuditOffset / rbacAuditLimit) + 1

	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListRBACAuditLogsWithResponse(context.Background(), &apiclient.ListRBACAuditLogsParams{
		Page:     &page,
		PageSize: &rbacAuditLimit,
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve RBAC audit logs: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("failed to retrieve RBAC audit logs: HTTP %d", resp.StatusCode())
	}
	logs := derefRBACAuditLogSlice(resp.JSON200.Data.Logs)
	total := derefInt(resp.JSON200.Data.Total)
	if len(logs) == 0 {
		fmt.Println("No RBAC audit logs found")
		return nil
	}
	fmt.Printf("RBAC audit logs (showing %d of %d):\n", len(logs), total)
	for _, e := range logs {
		printRBACAuditEntry(e)
	}
	return nil
}

func printRBACAuditEntry(e apiclient.RBACAuditLogEntry) { // NOSONAR -- domain-driven field count, mirrors the old CLI's printAuditEntry
	when := ""
	if e.CreatedAt != nil {
		when = e.CreatedAt.UTC().Format(time.RFC3339)
	}
	fmt.Printf("  [%s] %s", when, derefStr(e.Action))
	if e.ActorUserId != nil {
		fmt.Printf(" by user %d", *e.ActorUserId)
	}
	if e.TargetUserId != nil {
		fmt.Printf(" → user %d", *e.TargetUserId)
	}
	if e.GroupId != nil {
		fmt.Printf(" → group %d", *e.GroupId)
	}
	if e.RoleId != nil {
		fmt.Printf(" role %d", *e.RoleId)
	}
	if e.PermissionId != nil {
		fmt.Printf(" permission %d", *e.PermissionId)
	}
	if e.ProjectId != nil && *e.ProjectId != 0 {
		fmt.Printf(" @ project %d", *e.ProjectId)
	}
	if e.Details != nil && *e.Details != "" {
		fmt.Printf(" (%s)", *e.Details)
	}
	fmt.Println()
}

func derefRBACAuditLogSlice(s *[]apiclient.RBACAuditLogEntry) []apiclient.RBACAuditLogEntry {
	if s == nil {
		return nil
	}
	return *s
}

// ── export-matrix ───────────────────────────────────────────────────────────────

var (
	rbacExportMatrixFormat  string
	rbacExportMatrixProject string
	rbacExportMatrixOutput  string
)

var rbacExportMatrixCmd = &cobra.Command{
	Use:   "export-matrix",
	Short: "Export the deployment-wide RBAC permission matrix",
	Long: `Export every (user, role, permission, scope) tuple in the deployment.

Used by auditors for SOC2/ISO27001 access reviews. Output includes who holds
what role/permission in what scope (global, project, or environment).

Supports table (default), JSON, and CSV output formats.

Examples:
  keyorix-next rbac export-matrix
  keyorix-next rbac export-matrix --format csv --output access-review.csv
  keyorix-next rbac export-matrix --format json --project production`,
	RunE: runRBACExportMatrix,
}

func init() {
	rbacExportMatrixCmd.Flags().StringVar(&rbacExportMatrixFormat, "format", "table", "Output format: table, csv, or json")
	rbacExportMatrixCmd.Flags().StringVar(&rbacExportMatrixProject, "project", "", "Filter by project name (optional)")
	rbacExportMatrixCmd.Flags().StringVar(&rbacExportMatrixOutput, "output", "", "Write output to this file (default: stdout)")
	rbacCmd.AddCommand(rbacExportMatrixCmd)
}

// openSecureOutputFile opens path for --output. The permission matrix is
// deployment-wide access-control data (usernames, emails, every user/role/
// permission/scope tuple) -- sensitive enough that it must never land on disk
// world/group-readable, and must never silently overwrite an existing file. This
// module cannot import internal/securefiles (it is a separate Go module with no
// dependency on the root one, by ADR-108 Decision A's design) so this is a
// smaller, self-contained equivalent: O_EXCL refuses to open through or
// overwrite an already-existing path (matches the old CLI's own behavior), and
// 0600 keeps it off-limits to other local users. It does not walk each parent
// path component for a planted symlink the way internal/securefiles does.
func openSecureOutputFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is an operator-supplied CLI flag (--output), not attacker/network input
}

func runRBACExportMatrix(cmd *cobra.Command, args []string) error {
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	// Fetch fully into memory FIRST, and only open/truncate --output afterward:
	// openSecureOutputFile's O_CREATE means merely opening the destination
	// already leaves an (empty) file behind, even if the fetch that was
	// supposed to fill it then fails.
	write, err := fetchRBACExportMatrix(ctx, client)
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	if rbacExportMatrixOutput != "" {
		f, err := openSecureOutputFile(rbacExportMatrixOutput)
		if err != nil {
			return fmt.Errorf("cannot create output file %q (it may already exist — remove it or choose a different path): %w", rbacExportMatrixOutput, err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	return write(out)
}

func fetchRBACExportMatrix(ctx context.Context, client *apiclient.ClientWithResponses) (func(io.Writer) error, error) {
	var projectID *int
	if rbacExportMatrixProject != "" {
		id, err := resolveRBACProjectIDByName(ctx, client, rbacExportMatrixProject)
		if err != nil {
			return nil, err
		}
		projectID = &id
	}

	if rbacExportMatrixFormat == "csv" {
		params := &apiclient.GetPermissionMatrixParams{ProjectId: projectID, Format: &[]apiclient.GetPermissionMatrixParamsFormat{apiclient.Csv}[0]}
		resp, err := client.GetPermissionMatrixWithResponse(ctx, params)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch permission matrix (CSV): %w", err)
		}
		if resp.HTTPResponse == nil || resp.HTTPResponse.StatusCode != 200 {
			return nil, fmt.Errorf("failed to fetch permission matrix (CSV): HTTP %d", resp.StatusCode())
		}
		body := resp.Body
		return func(out io.Writer) error {
			_, werr := out.Write(body)
			return werr
		}, nil
	}

	resp, err := client.GetPermissionMatrixWithResponse(ctx, &apiclient.GetPermissionMatrixParams{ProjectId: projectID})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch permission matrix: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return nil, fmt.Errorf("failed to fetch permission matrix: HTTP %d", resp.StatusCode())
	}
	rows := derefPermissionMatrixRowSlice(resp.JSON200.Data.Rows)
	return func(out io.Writer) error {
		return writeMatrix(out, rows, rbacExportMatrixFormat)
	}, nil
}

func writeMatrix(out io.Writer, rows []apiclient.PermissionMatrixRow, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case "csv":
		w := csv.NewWriter(out)
		_ = w.Write([]string{
			"username", "email", "role", "permission", "resource", "action",
			"scope", "project", "environment", "expires_at",
		})
		for _, r := range rows {
			_ = w.Write(matrixRowToCSV(r))
		}
		w.Flush()
		return w.Error()
	default:
		return writeMatrixTable(out, rows)
	}
}

func writeMatrixTable(out io.Writer, rows []apiclient.PermissionMatrixRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(out, "No permission grants found.")
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USERNAME\tEMAIL\tROLE\tPERMISSION\tSCOPE\tPROJECT\tEXPIRES")
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			derefStr(r.Username), derefStr(r.Email), derefStr(r.RoleName), derefStr(r.PermissionName),
			derefMatrixScope(r.Scope), derefStr(r.ProjectName), matrixExpiresAt(r.ExpiresAt))
	}
	return tw.Flush()
}

func matrixRowToCSV(r apiclient.PermissionMatrixRow) []string {
	return []string{
		derefStr(r.Username), derefStr(r.Email), derefStr(r.RoleName), derefStr(r.PermissionName),
		derefStr(r.Resource), derefStr(r.Action), derefMatrixScope(r.Scope), derefStr(r.ProjectName), derefStr(r.EnvironmentName), matrixExpiresAt(r.ExpiresAt),
	}
}

func matrixExpiresAt(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func derefMatrixScope(s *apiclient.PermissionMatrixRowScope) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

func derefPermissionMatrixRowSlice(s *[]apiclient.PermissionMatrixRow) []apiclient.PermissionMatrixRow {
	if s == nil {
		return nil
	}
	return *s
}
