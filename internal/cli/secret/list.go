package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	listProjectName string // project name; resolved via ADR-016 chain when --project is omitted
	listEnv         uint
	listLimit       int
	listOffset      int
	listSearch      string
	listFormat      string
	listFolderID    uint
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets",
	Long: `List secrets with filtering and pagination.

In local mode the CLI has direct database access and acts as an admin tool,
so all secrets are listed regardless of owner. In remote mode the server
applies authentication-based filtering automatically.

Examples:
  keyorix secret list
  keyorix secret list --project my-project --environment 1
  keyorix secret list --limit 10
  keyorix secret list --format json`,
	RunE: runList,
}

func init() {
	listCmd.Flags().StringVar(&listProjectName, "project", "", "Project name (overrides KEYORIX_PROJECT and active project)")
	listCmd.Flags().UintVar(&listEnv, "environment", 0, "Filter by environment ID (0 = all)")
	listCmd.Flags().IntVar(&listLimit, "limit", 50, "Maximum number of results")
	listCmd.Flags().IntVar(&listOffset, "offset", 0, "Number of results to skip")
	listCmd.Flags().StringVar(&listSearch, "search", "", "Search query")
	listCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table, json)")
	listCmd.Flags().UintVar(&listFolderID, "folder", 0, "Filter to direct children of this folder node ID (0 = all)")
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runListRemote(ctx, rc)
	}
	return runListEmbedded(ctx)
}

// ── Remote mode ───────────────────────────────────────────────────────────────

// resolveProjectIDParam resolves a project name to its ID via the API and
// returns the query parameter string to append (e.g. "&project_id=42"), or ""
// when projectName is empty.
func resolveProjectIDParam(ctx context.Context, rc *common.RemoteClient, projectName string) (string, error) {
	if projectName == "" {
		return "", nil
	}
	// rc.Get strips the {"data":…} envelope — decode the inner payload directly.
	var resp struct {
		Projects []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
		return "", fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range resp.Projects {
		if strings.EqualFold(p.Name, projectName) {
			return fmt.Sprintf("&project_id=%d", p.ID), nil
		}
	}
	return "", fmt.Errorf("project %q not found — run 'keyorix project list' to see available projects", projectName)
}

func runListRemote(ctx context.Context, rc *common.RemoteClient) error {
	page := (listOffset / listLimit) + 1
	path := fmt.Sprintf("/api/v1/secrets?page=%d&page_size=%d", page, listLimit)

	// Resolve project name → ID if a project scope is requested.
	// ResolveProject ignores the error when nothing is set (project scope is optional for list).
	projectName, _ := common.ResolveProject(listProjectName)
	projectParam, err := resolveProjectIDParam(ctx, rc, projectName)
	if err != nil {
		return err
	}
	path += projectParam

	if listEnv != 0 {
		path += fmt.Sprintf("&environment_id=%d", listEnv)
	}
	if listFolderID != 0 {
		path += fmt.Sprintf("&parent_id=%d", listFolderID)
	}

	var resp models.SecretListResponse
	if err := rc.Get(ctx, path, &resp); err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	// Extract *SecretNode from each SecretWithSharingInfo for display.
	secrets := make([]*models.SecretNode, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		if s.SecretNode != nil {
			secrets = append(secrets, s.SecretNode)
		}
	}

	filter := &coreStorage.SecretFilter{
		Page:     page,
		PageSize: listLimit,
	}
	if listEnv != 0 {
		filter.EnvironmentID = &listEnv
	}

	switch listFormat {
	case "json":
		displaySecretsJSON(secrets, resp.Total, filter)
	case "table": //nolint:goconst
		displaySecretsTable(secrets, resp.Total, filter)
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", listFormat)
	}
	return nil
}

// ── Embedded mode ─────────────────────────────────────────────────────────────

func runListEmbedded(ctx context.Context) error {
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	filter := &coreStorage.SecretFilter{
		Page:     (listOffset / listLimit) + 1,
		PageSize: listLimit,
	}

	// Resolve project name → ID if a project scope is requested.
	projectName, _ := common.ResolveProject(listProjectName)
	if projectName != "" {
		projectID, err := common.LookupProjectIDByName(ctx, service.Storage(), projectName)
		if err != nil {
			return err
		}
		filter.ProjectID = &projectID
	}

	if listEnv != 0 {
		filter.EnvironmentID = &listEnv
	}
	if listFolderID != 0 {
		filter.ParentID = &listFolderID
	}

	secrets, total, err := service.ListSecrets(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	switch listFormat {
	case "json":
		displaySecretsJSON(secrets, total, filter)
	case "table":
		displaySecretsTable(secrets, total, filter)
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", listFormat)
	}
	return nil
}

// ── Display ───────────────────────────────────────────────────────────────────

func displaySecretsTable(secrets []*models.SecretNode, total int64, filter *coreStorage.SecretFilter) {
	fmt.Printf("Secrets List\n")
	fmt.Printf("============\n")

	if listSearch != "" {
		fmt.Printf("Search: %s (note: search filtering not yet implemented)\n", listSearch)
	}

	nsLabel := "all"
	if filter.ProjectID != nil {
		nsLabel = fmt.Sprintf("%d", *filter.ProjectID)
	} else if listProjectName != "" {
		nsLabel = listProjectName
	}
	envLabel := "all"
	if filter.EnvironmentID != nil {
		envLabel = fmt.Sprintf("%d", *filter.EnvironmentID)
	}
	fmt.Printf("Project: %s, Environment: %s\n", nsLabel, envLabel)

	offset := (filter.Page - 1) * filter.PageSize
	fmt.Printf("Total: %d, Showing: %d (offset: %d, limit: %d)\n\n", total, len(secrets), offset, filter.PageSize)

	if len(secrets) == 0 {
		fmt.Printf("No secrets found.\n")
		return
	}

	fmt.Printf("%-5s %-20s %-12s %-8s %-20s %-20s\n",
		"ID", "NAME", "TYPE", "STATUS", "CREATED", "EXPIRES")
	fmt.Printf("%-5s %-20s %-12s %-8s %-20s %-20s\n",
		"-----", "--------------------", "------------", "--------", "--------------------", "--------------------")

	for _, secret := range secrets {
		expires := "Never"
		if secret.Expiration != nil {
			expires = secret.Expiration.Format("2006-01-02 15:04")
			if time.Now().After(*secret.Expiration) {
				expires += " (EXPIRED)"
			}
		}
		fmt.Printf("%-5d %-20s %-12s %-8s %-20s %-20s\n",
			secret.ID,
			truncateString(secret.Name, 20),
			truncateString(secret.Type, 12),
			secret.Status,
			secret.CreatedAt.Format("2006-01-02 15:04"),
			truncateString(expires, 20))
	}

	if total > int64(filter.PageSize) {
		fmt.Printf("\nPagination: Showing %d-%d of %d total\n",
			offset+1,
			min(offset+len(secrets), int(total)),
			total)
		if offset+filter.PageSize < int(total) {
			fmt.Printf("Use --offset %d to see more results\n", offset+filter.PageSize)
		}
	}
}

// jsonSecretEntry is the per-secret shape for `secret list --format json`.
// Built and marshaled via encoding/json (not fmt.Printf string interpolation)
// so a secret name (or any other string field) containing quotes/control
// characters is correctly escaped rather than able to break out of the JSON
// string and inject arbitrary keys (#354).
type jsonSecretEntry struct {
	ID            uint    `json:"id"`
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Status        string  `json:"status"`
	ProjectID     uint    `json:"project_id"`
	EnvironmentID uint    `json:"environment_id"`
	CreatedBy     string  `json:"created_by"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	MaxReads      *int    `json:"max_reads,omitempty"`
	Expiration    *string `json:"expiration,omitempty"`
}

type jsonSecretsOutput struct {
	Total   int64             `json:"total"`
	Offset  int               `json:"offset"`
	Limit   int               `json:"limit"`
	Count   int               `json:"count"`
	Secrets []jsonSecretEntry `json:"secrets"`
}

func displaySecretsJSON(secrets []*models.SecretNode, total int64, filter *coreStorage.SecretFilter) {
	offset := (filter.Page - 1) * filter.PageSize

	out := jsonSecretsOutput{
		Total:   total,
		Offset:  offset,
		Limit:   filter.PageSize,
		Count:   len(secrets),
		Secrets: make([]jsonSecretEntry, 0, len(secrets)),
	}
	for _, secret := range secrets {
		entry := jsonSecretEntry{
			ID:            secret.ID,
			Name:          secret.Name,
			Type:          secret.Type,
			Status:        secret.Status,
			ProjectID:     secret.ProjectID,
			EnvironmentID: secret.EnvironmentID,
			CreatedBy:     secret.CreatedBy,
			CreatedAt:     secret.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     secret.UpdatedAt.Format(time.RFC3339),
			MaxReads:      secret.MaxReads,
		}
		if secret.Expiration != nil {
			exp := secret.Expiration.Format(time.RFC3339)
			entry.Expiration = &exp
		}
		out.Secrets = append(out.Secrets, entry)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON output: %v\n", err)
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
