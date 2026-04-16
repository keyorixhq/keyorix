package secret

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	listNamespace uint
	listZone      uint
	listEnv       uint
	listLimit     int
	listOffset    int
	listSearch    string
	listFormat    string
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
  keyorix secret list --namespace 1 --zone 1 --environment 1
  keyorix secret list --limit 10
  keyorix secret list --format json`,
	RunE: runList,
}

func init() {
	listCmd.Flags().UintVar(&listNamespace, "namespace", 0, "Filter by namespace ID (0 = all)")
	listCmd.Flags().UintVar(&listZone, "zone", 0, "Filter by zone ID (0 = all)")
	listCmd.Flags().UintVar(&listEnv, "environment", 0, "Filter by environment ID (0 = all)")
	listCmd.Flags().IntVar(&listLimit, "limit", 50, "Maximum number of results")
	listCmd.Flags().IntVar(&listOffset, "offset", 0, "Number of results to skip")
	listCmd.Flags().StringVar(&listSearch, "search", "", "Search query")
	listCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table, json)")
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runListRemote(ctx, rc)
	}
	return runListEmbedded(ctx)
}

// ── Remote mode ───────────────────────────────────────────────────────────────

func runListRemote(ctx context.Context, rc *common.RemoteClient) error {
	page := (listOffset / listLimit) + 1
	path := fmt.Sprintf("/api/v1/secrets?page=%d&page_size=%d", page, listLimit)
	if listNamespace != 0 {
		path += fmt.Sprintf("&namespace_id=%d", listNamespace)
	}
	if listZone != 0 {
		path += fmt.Sprintf("&zone_id=%d", listZone)
	}
	if listEnv != 0 {
		path += fmt.Sprintf("&environment_id=%d", listEnv)
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
	if listNamespace != 0 {
		filter.NamespaceID = &listNamespace
	}
	if listZone != 0 {
		filter.ZoneID = &listZone
	}
	if listEnv != 0 {
		filter.EnvironmentID = &listEnv
	}

	switch listFormat {
	case "json":
		displaySecretsJSON(secrets, resp.Total, filter)
	case "table":
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
	if listNamespace != 0 {
		filter.NamespaceID = &listNamespace
	}
	if listZone != 0 {
		filter.ZoneID = &listZone
	}
	if listEnv != 0 {
		filter.EnvironmentID = &listEnv
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
	if filter.NamespaceID != nil {
		nsLabel = fmt.Sprintf("%d", *filter.NamespaceID)
	}
	zoneLabel := "all"
	if filter.ZoneID != nil {
		zoneLabel = fmt.Sprintf("%d", *filter.ZoneID)
	}
	envLabel := "all"
	if filter.EnvironmentID != nil {
		envLabel = fmt.Sprintf("%d", *filter.EnvironmentID)
	}
	fmt.Printf("Namespace: %s, Zone: %s, Environment: %s\n", nsLabel, zoneLabel, envLabel)

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

func displaySecretsJSON(secrets []*models.SecretNode, total int64, filter *coreStorage.SecretFilter) {
	offset := (filter.Page - 1) * filter.PageSize

	fmt.Printf("{\n")
	fmt.Printf("  \"total\": %d,\n", total)
	fmt.Printf("  \"offset\": %d,\n", offset)
	fmt.Printf("  \"limit\": %d,\n", filter.PageSize)
	fmt.Printf("  \"count\": %d,\n", len(secrets))
	fmt.Printf("  \"secrets\": [\n")

	for i, secret := range secrets {
		fmt.Printf("    {\n")
		fmt.Printf("      \"id\": %d,\n", secret.ID)
		fmt.Printf("      \"name\": \"%s\",\n", secret.Name)
		fmt.Printf("      \"type\": \"%s\",\n", secret.Type)
		fmt.Printf("      \"status\": \"%s\",\n", secret.Status)
		fmt.Printf("      \"namespace_id\": %d,\n", secret.NamespaceID)
		fmt.Printf("      \"zone_id\": %d,\n", secret.ZoneID)
		fmt.Printf("      \"environment_id\": %d,\n", secret.EnvironmentID)
		fmt.Printf("      \"created_by\": \"%s\",\n", secret.CreatedBy)
		fmt.Printf("      \"created_at\": \"%s\",\n", secret.CreatedAt.Format(time.RFC3339))
		fmt.Printf("      \"updated_at\": \"%s\"", secret.UpdatedAt.Format(time.RFC3339))
		if secret.MaxReads != nil {
			fmt.Printf(",\n      \"max_reads\": %d", *secret.MaxReads)
		}
		if secret.Expiration != nil {
			fmt.Printf(",\n      \"expiration\": \"%s\"", secret.Expiration.Format(time.RFC3339))
		}
		fmt.Printf("\n    }")
		if i < len(secrets)-1 {
			fmt.Printf(",")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("  ]\n")
	fmt.Printf("}\n")
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
