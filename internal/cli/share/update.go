package share

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	updateShareID    uint
	updatePermission string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a share's permission",
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().UintVar(&updateShareID, "share-id", 0, "Share ID (required)")
	updateCmd.Flags().StringVar(&updatePermission, "permission", "", "Permission level (read or write) (required)")

	updateCmd.MarkFlagRequired("share-id")   // #nosec G104
	updateCmd.MarkFlagRequired("permission") // #nosec G104
}

func runUpdate(cmd *cobra.Command, args []string) error {
	// Validate permission
	if updatePermission != "read" && updatePermission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", updatePermission)
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
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize storage and service
	storage := store.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	// Create update request
	req := &core.UpdateShareRequest{
		ShareID:    updateShareID,
		Permission: updatePermission,
		UpdatedBy:  1, // CLI user ID
	}

	// Call service
	ctx := context.Background()
	shareRecord, err := service.UpdateSharePermission(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update share permission: %w", err)
	}

	// Print result
	fmt.Printf("✅ Share permission updated successfully!\n")
	fmt.Printf("Share ID: %d\n", shareRecord.ID)
	fmt.Printf("Secret ID: %d\n", shareRecord.SecretID)
	fmt.Printf("Owner ID: %d\n", shareRecord.OwnerID)
	fmt.Printf("Recipient ID: %d\n", shareRecord.RecipientID)
	fmt.Printf("Is Group: %t\n", shareRecord.IsGroup)
	fmt.Printf("Permission: %s\n", shareRecord.Permission)
	fmt.Printf("Updated At: %s\n", shareRecord.UpdatedAt.Format("2006-01-02 15:04:05"))

	return nil
}
