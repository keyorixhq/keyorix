package secret

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

Examples:
  keyorix secret list
  keyorix secret list --namespace 1 --zone 1 --environment 1
  keyorix secret list --search "password" --limit 10
  keyorix secret list --format table  # table or json`,
	RunE: runList,
}

func init() {
	listCmd.Flags().UintVar(&listNamespace, "namespace", 1, "Namespace ID")
	listCmd.Flags().UintVar(&listZone, "zone", 1, "Zone ID")
	listCmd.Flags().UintVar(&listEnv, "environment", 1, "Environment ID")
	listCmd.Flags().IntVar(&listLimit, "limit", 50, "Maximum number of results")
	listCmd.Flags().IntVar(&listOffset, "offset", 0, "Number of results to skip")
	listCmd.Flags().StringVar(&listSearch, "search", "", "Search query")
	listCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table, json)")
}

func runList(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Connect to database
	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate models (ensure tables exist)
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize storage and core service
	storageImpl := local.NewLocalStorage(db)
	service := core.NewKeyorixCore(storageImpl)

	// Create context
	ctx := context.Background()

	// Build filter options
	namespaceID := listNamespace
	zoneID := listZone
	environmentID := listEnv
	filter := &coreStorage.SecretFilter{
		NamespaceID:   &namespaceID,
		ZoneID:        &zoneID,
		EnvironmentID: &environmentID,
		Page:          (listOffset / listLimit) + 1,
		PageSize:      listLimit,
	}

	// Note: Search functionality would need to be implemented in the storage layer
	// For now, we'll list all secrets and can add search filtering later

	// Get secrets
	secrets, total, err := service.ListSecrets(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	// Display results
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

func displaySecretsTable(secrets []*models.SecretNode, total int64, filter *coreStorage.SecretFilter) {
	fmt.Printf("🔐 Secrets List\n")
	fmt.Printf("===============\n")

	if listSearch != "" {
		fmt.Printf("Search: %s (note: search filtering not yet implemented)\n", listSearch)
	}
	fmt.Printf("Namespace: %d, Zone: %d, Environment: %d\n", *filter.NamespaceID, *filter.ZoneID, *filter.EnvironmentID)
	
	offset := (filter.Page - 1) * filter.PageSize
	fmt.Printf("Total: %d, Showing: %d (offset: %d, limit: %d)\n\n", total, len(secrets), offset, filter.PageSize)

	if len(secrets) == 0 {
		fmt.Printf("No secrets found.\n")
		return
	}

	// Table header
	fmt.Printf("%-5s %-20s %-12s %-8s %-20s %-20s\n",
		"ID", "NAME", "TYPE", "STATUS", "CREATED", "EXPIRES")
	fmt.Printf("%-5s %-20s %-12s %-8s %-20s %-20s\n",
		"-----", "--------------------", "------------", "--------", "--------------------", "--------------------")

	// Table rows
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

	// Pagination info
	if total > int64(filter.PageSize) {
		fmt.Printf("\n📄 Pagination: Showing %d-%d of %d total\n",
			offset+1,
			min(offset+len(secrets), int(total)),
			total)

		if offset+filter.PageSize < int(total) {
			fmt.Printf("💡 Use --offset %d to see more results\n", offset+filter.PageSize)
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
		fmt.Printf("      \"updated_at\": \"%s\",\n", secret.UpdatedAt.Format(time.RFC3339))

		if secret.MaxReads != nil {
			fmt.Printf("      \"max_reads\": %d,\n", *secret.MaxReads)
		}

		if secret.Expiration != nil {
			fmt.Printf("      \"expiration\": \"%s\",\n", secret.Expiration.Format(time.RFC3339))
		}

		fmt.Printf("      \"tags\": []\n") // Tags field can be added later
		fmt.Printf("    }")
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
