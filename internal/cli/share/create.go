package share

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	createSecretID   uint
	createRecipientID uint
	createIsGroup    bool
	createPermission string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Share a secret with another user or group",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().UintVar(&createSecretID, "secret-id", 0, "Secret ID (required)")
	createCmd.Flags().UintVar(&createRecipientID, "recipient-id", 0, "Recipient ID (required)")
	createCmd.Flags().BoolVar(&createIsGroup, "is-group", false, "Whether the recipient is a group")
	createCmd.Flags().StringVar(&createPermission, "permission", "read", "Permission level (read or write)")
	
	createCmd.MarkFlagRequired("secret-id")
	createCmd.MarkFlagRequired("recipient-id")
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Validate permission
	if createPermission != "read" && createPermission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", createPermission)
	}

	// Load config and connect to database
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate models (ensure tables exist)
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize storage and service
	storage := local.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	// Create context
	ctx := context.Background()
	
	var shareRecord *models.ShareRecord
	
	// Handle group sharing differently
	if createIsGroup {
		// Create group share request
		req := &core.GroupShareSecretRequest{
			SecretID:   createSecretID,
			GroupID:    createRecipientID,
			Permission: createPermission,
			SharedBy:   1, // CLI user ID
		}
		
		// Call service for group sharing
		shareRecord, err = service.ShareSecretWithGroup(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to share secret with group: %w", err)
		}
	} else {
		// Create user share request
		req := &core.ShareSecretRequest{
			SecretID:    createSecretID,
			RecipientID: createRecipientID,
			IsGroup:     false,
			Permission:  createPermission,
			SharedBy:    1, // CLI user ID
		}
		
		// Call service for user sharing
		shareRecord, err = service.ShareSecret(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to share secret with user: %w", err)
		}
	}

	// Print result
	fmt.Printf("✅ Secret shared successfully!\n")
	fmt.Printf("Share ID: %d\n", shareRecord.ID)
	fmt.Printf("Secret ID: %d\n", shareRecord.SecretID)
	fmt.Printf("Owner ID: %d\n", shareRecord.OwnerID)
	fmt.Printf("Recipient ID: %d\n", shareRecord.RecipientID)
	fmt.Printf("Is Group: %t\n", shareRecord.IsGroup)
	fmt.Printf("Permission: %s\n", shareRecord.Permission)
	fmt.Printf("Created At: %s\n", shareRecord.CreatedAt.Format("2006-01-02 15:04:05"))

	return nil
}