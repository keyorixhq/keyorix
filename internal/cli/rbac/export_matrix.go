package rbac

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var exportMatrixCmd = &cobra.Command{
	Use:   "export-matrix",
	Short: "Export the deployment-wide RBAC permission matrix",
	Long: `Export every (user, role, permission, scope) tuple in the deployment.

Used by auditors for SOC2/ISO27001 access reviews. Output includes who holds
what role/permission in what scope (global, project, or environment).

Supports table (default), JSON, and CSV output formats.

Examples:
  keyorix rbac export-matrix
  keyorix rbac export-matrix --format csv --output access-review.csv
  keyorix rbac export-matrix --format json --project production`,
	RunE: runExportMatrix,
}

var (
	exportMatrixFormat  string
	exportMatrixProject string
	exportMatrixOutput  string
)

func init() {
	exportMatrixCmd.Flags().StringVar(&exportMatrixFormat, "format", "table", "Output format: table, csv, or json")
	exportMatrixCmd.Flags().StringVar(&exportMatrixProject, "project", "", "Filter by project name (optional)")
	exportMatrixCmd.Flags().StringVar(&exportMatrixOutput, "output", "", "Write output to this file (default: stdout)")
}

// remoteMatrixRow is the JSON shape the server's GET /api/v1/rbac/permission-matrix
// endpoint returns for each entry in the "rows" array.
type remoteMatrixRow struct {
	UserID          uint       `json:"user_id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	RoleID          uint       `json:"role_id"`
	RoleName        string     `json:"role_name"`
	PermissionName  string     `json:"permission_name"`
	Resource        string     `json:"resource"`
	Action          string     `json:"action"`
	Scope           string     `json:"scope"`
	ProjectID       uint       `json:"project_id"`
	ProjectName     string     `json:"project_name"`
	EnvironmentID   uint       `json:"environment_id"`
	EnvironmentName string     `json:"environment_name"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

func runExportMatrix(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	out := io.Writer(os.Stdout)
	if exportMatrixOutput != "" {
		f, err := os.Create(filepath.Clean(exportMatrixOutput))
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runExportMatrixRemote(ctx, rc, out)
	}

	// Embedded (direct-DB) mode.
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	coreService := core.NewKeyorixCore(st)

	projectID := uint(0)
	if exportMatrixProject != "" {
		projectID, err = common.LookupProjectIDByName(ctx, st, exportMatrixProject)
		if err != nil {
			return fmt.Errorf("failed to resolve project: %w", err)
		}
	}

	rows, err := coreService.GetPermissionMatrix(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to build permission matrix: %w", err)
	}

	return writeMatrixEmbedded(out, rows, exportMatrixFormat)
}

func runExportMatrixRemote(ctx context.Context, rc *common.RemoteClient, out io.Writer) error {
	path := "/api/v1/rbac/permission-matrix"
	if exportMatrixProject != "" {
		projectID, err := resolveProjectIDByName(ctx, rc, exportMatrixProject)
		if err != nil {
			return err
		}
		if exportMatrixFormat == "csv" {
			// Request CSV directly from the server to avoid double-serialisation.
			data, err := rc.GetRaw(ctx, fmt.Sprintf("%s?project_id=%d&format=csv", path, projectID))
			if err != nil {
				return fmt.Errorf("failed to fetch permission matrix (CSV): %w", err)
			}
			_, err = out.Write(data)
			return err
		}
		path = fmt.Sprintf("%s?project_id=%d", path, projectID)
	} else if exportMatrixFormat == "csv" {
		data, err := rc.GetRaw(ctx, path+"?format=csv")
		if err != nil {
			return fmt.Errorf("failed to fetch permission matrix (CSV): %w", err)
		}
		_, err = out.Write(data)
		return err
	}

	var resp struct {
		Rows  []remoteMatrixRow `json:"rows"`
		Total int               `json:"total"`
	}
	if err := rc.Get(ctx, path, &resp); err != nil {
		return fmt.Errorf("failed to fetch permission matrix: %w", err)
	}
	return writeMatrixRemote(out, resp.Rows, exportMatrixFormat)
}

func writeMatrixRemote(out io.Writer, rows []remoteMatrixRow, format string) error {
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
			_ = w.Write(remoteRowToCSV(r))
		}
		w.Flush()
		return w.Error()
	default:
		return writeRemoteTable(out, rows)
	}
}

func writeMatrixEmbedded(out io.Writer, rows []*core.PermissionMatrixRow, format string) error {
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
			expiresAt := "never"
			if r.ExpiresAt != nil {
				expiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
			}
			_ = w.Write([]string{
				common.CSVSafe(r.Username), common.CSVSafe(r.Email), common.CSVSafe(r.RoleName), common.CSVSafe(r.PermissionName),
				common.CSVSafe(r.Resource), common.CSVSafe(r.Action), common.CSVSafe(r.Scope), common.CSVSafe(r.ProjectName), common.CSVSafe(r.EnvironmentName), expiresAt,
			})
		}
		w.Flush()
		return w.Error()
	default:
		return writeEmbeddedTable(out, rows)
	}
}

func writeEmbeddedTable(out io.Writer, rows []*core.PermissionMatrixRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(out, "No permission grants found.")
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USERNAME\tEMAIL\tROLE\tPERMISSION\tSCOPE\tPROJECT\tEXPIRES")
	for _, r := range rows {
		expiresAt := "never"
		if r.ExpiresAt != nil {
			expiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Username, r.Email, r.RoleName, r.PermissionName,
			r.Scope, r.ProjectName, expiresAt)
	}
	return tw.Flush()
}

func writeRemoteTable(out io.Writer, rows []remoteMatrixRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(out, "No permission grants found.")
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USERNAME\tEMAIL\tROLE\tPERMISSION\tSCOPE\tPROJECT\tEXPIRES")
	for _, r := range rows {
		expiresAt := "never"
		if r.ExpiresAt != nil {
			expiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Username, r.Email, r.RoleName, r.PermissionName,
			r.Scope, r.ProjectName, expiresAt)
	}
	return tw.Flush()
}

func remoteRowToCSV(r remoteMatrixRow) []string {
	expiresAt := "never"
	if r.ExpiresAt != nil {
		expiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return []string{
		common.CSVSafe(r.Username), common.CSVSafe(r.Email), common.CSVSafe(r.RoleName), common.CSVSafe(r.PermissionName),
		common.CSVSafe(r.Resource), common.CSVSafe(r.Action), common.CSVSafe(r.Scope), common.CSVSafe(r.ProjectName), common.CSVSafe(r.EnvironmentName), expiresAt,
	}
}
