package secret

import (
	"context"
	"fmt"
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
	getID        uint
	getName      string
	getShowValue bool
	getNamespace uint
	getZone      uint
	getEnv       uint
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a secret",
	Long: `Retrieve a secret by ID or name.

Examples:
  keyorix secret get --id 123
  keyorix secret get --name "db-password" --namespace 1 --zone 1 --environment 1
  keyorix secret get --id 123 --show-value  # Show decrypted value`,
	RunE: runGet,
}

func init() {
	getCmd.Flags().UintVar(&getID, "id", 0, "Secret ID")
	getCmd.Flags().StringVar(&getName, "name", "", "Secret name")
	getCmd.Flags().UintVar(&getNamespace, "namespace", 1, "Namespace ID (required with --name)")
	getCmd.Flags().UintVar(&getZone, "zone", 1, "Zone ID (required with --name)")
	getCmd.Flags().UintVar(&getEnv, "environment", 1, "Environment ID (required with --name)")
	getCmd.Flags().BoolVar(&getShowValue, "show-value", false, "Show decrypted secret value")
}

func runGet(cmd *cobra.Command, args []string) error {
	if getID == 0 && getName == "" {
		return fmt.Errorf("either --id or --name is required")
	}

	// Load configuration
	cfg, err := config.Load("keyorix.yaml")
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
	storage := local.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	ctx := context.Background()
	var secret *models.SecretNode

	// Get secret by ID or name
	if getID != 0 {
		secret, err = service.GetSecret(ctx, getID)
		if err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}
	} else {
		// Find by name using storage interface
		secret, err = storage.GetSecretByName(ctx, getName, getNamespace, getZone, getEnv)
		if err != nil {
			return fmt.Errorf("secret not found: %w", err)
		}
	}

	// Display secret information
	displaySecret(secret)

	return nil
}

func displaySecret(secret *models.SecretNode) {
	fmt.Printf("🔐 Secret Information\n")
	fmt.Printf("====================\n")
	fmt.Printf("ID: %d\n", secret.ID)
	fmt.Printf("Name: %s\n", secret.Name)
	fmt.Printf("Type: %s\n", secret.Type)
	fmt.Printf("Status: %s\n", secret.Status)
	fmt.Printf("Namespace: %d\n", secret.NamespaceID)
	fmt.Printf("Zone: %d\n", secret.ZoneID)
	fmt.Printf("Environment: %d\n", secret.EnvironmentID)
	fmt.Printf("Created By: %s\n", secret.CreatedBy)
	fmt.Printf("Created: %s\n", secret.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated: %s\n", secret.UpdatedAt.Format(time.RFC3339))

	if secret.MaxReads != nil {
		fmt.Printf("Max Reads: %d\n", *secret.MaxReads)
	}

	if secret.Expiration != nil {
		fmt.Printf("Expires: %s\n", secret.Expiration.Format(time.RFC3339))
		if time.Now().After(*secret.Expiration) {
			fmt.Printf("⚠️  Status: EXPIRED\n")
		}
	}

	if getShowValue {
		fmt.Printf("\n🔓 Decrypted Value\n")
		fmt.Printf("==================\n")
		fmt.Printf("⚠️  Note: Value decryption not yet implemented in new architecture\n")
		fmt.Printf("💡 This will be added in the next phase\n")
	} else {
		fmt.Printf("\n💡 Use --show-value to display the decrypted value\n")
	}
}


