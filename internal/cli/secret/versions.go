package secret

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	versionsID     uint
	versionsFormat string
)

var versionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List secret versions",
	Long: `List all versions of a secret.

Examples:
  keyorix secret versions --id 123
  keyorix secret versions --id 123 --format json`,
	RunE: runVersions,
}

func init() {
	versionsCmd.Flags().UintVar(&versionsID, "id", 0, "Secret ID (required)")
	versionsCmd.Flags().StringVar(&versionsFormat, "format", "table", "Output format (table, json)")
}

func runVersions(cmd *cobra.Command, args []string) error {
	if versionsID == 0 {
		return fmt.Errorf("secret ID is required (use --id)")
	}

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

	// Get secret info
	secret, err := service.GetSecret(ctx, versionsID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	// Get versions
	versions, err := service.GetSecretVersions(ctx, versionsID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	// Display results
	switch versionsFormat {
	case "json":
		displayVersionsJSON(secret, versions)
	case "table":
		displayVersionsTable(secret, versions)
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", versionsFormat)
	}

	return nil
}

func displayVersionsTable(secret *models.SecretNode, versions []*models.SecretVersion) {
	fmt.Printf("📚 Secret Versions\n")
	fmt.Printf("==================\n")
	fmt.Printf("Secret: %s (ID: %d)\n", secret.Name, secret.ID)
	fmt.Printf("Total Versions: %d\n\n", len(versions))

	if len(versions) == 0 {
		fmt.Printf("No versions found.\n")
		return
	}

	// Table header
	fmt.Printf("%-8s %-10s %-10s %-20s %-15s\n",
		"VERSION", "SIZE", "READS", "CREATED", "ALGORITHM")
	fmt.Printf("%-8s %-10s %-10s %-20s %-15s\n",
		"--------", "----------", "----------", "--------------------", "---------------")

	// Table rows
	for _, version := range versions {
		// Parse encryption metadata to get algorithm
		algorithm := "Unknown"
		if len(version.EncryptionMetadata) > 0 {
			// Try to extract algorithm from JSON metadata
			// This is a simplified approach - in production you'd properly parse JSON
			metaStr := string(version.EncryptionMetadata)
			if strings.Contains(metaStr, "AES-256-GCM") {
				algorithm = "AES-256-GCM"
			}
		}

		fmt.Printf("%-8d %-10s %-10d %-20s %-15s\n",
			version.VersionNumber,
			formatBytes(len(version.EncryptedValue)),
			version.ReadCount,
			version.CreatedAt.Format("2006-01-02 15:04:05"),
			algorithm)
	}

	// Show latest version info
	if len(versions) > 0 {
		latest := versions[len(versions)-1]
		fmt.Printf("\n💡 Latest Version: %d (Created: %s)\n",
			latest.VersionNumber,
			latest.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}

func displayVersionsJSON(secret *models.SecretNode, versions []*models.SecretVersion) {
	fmt.Printf("{\n")
	fmt.Printf("  \"secret\": {\n")
	fmt.Printf("    \"id\": %d,\n", secret.ID)
	fmt.Printf("    \"name\": \"%s\",\n", secret.Name)
	fmt.Printf("    \"type\": \"%s\"\n", secret.Type)
	fmt.Printf("  },\n")
	fmt.Printf("  \"total_versions\": %d,\n", len(versions))
	fmt.Printf("  \"versions\": [\n")

	for i, version := range versions {
		fmt.Printf("    {\n")
		fmt.Printf("      \"id\": %d,\n", version.ID)
		fmt.Printf("      \"version_number\": %d,\n", version.VersionNumber)
		fmt.Printf("      \"size_bytes\": %d,\n", len(version.EncryptedValue))
		fmt.Printf("      \"read_count\": %d,\n", version.ReadCount)
		fmt.Printf("      \"created_at\": \"%s\"", version.CreatedAt.Format(time.RFC3339))

		if len(version.EncryptionMetadata) > 0 {
			fmt.Printf(",\n      \"encryption_metadata\": %s", string(version.EncryptionMetadata))
		}

		fmt.Printf("\n    }")
		if i < len(versions)-1 {
			fmt.Printf(",")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("  ]\n")
	fmt.Printf("}\n")
}

func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
