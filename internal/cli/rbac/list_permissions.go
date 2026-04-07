package rbac

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

var listPermissionsCmd = &cobra.Command{
	Use:   "list-permissions",
	Short: "List all permissions for a user",
	Long:  "List all permissions assigned to a user through their roles",
	RunE:  runListPermissions,
}

var listPermissionsUserEmail string

func init() {
	listPermissionsCmd.Flags().StringVar(&listPermissionsUserEmail, "user", "", "User email address (required)")
	_ = listPermissionsCmd.MarkFlagRequired("user")
}

func runListPermissions(cmd *cobra.Command, args []string) error {
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

	// Auto-migrate models
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Role{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize storage and core service
	storage := local.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	// Create context
	ctx := context.Background()

	permissions, err := service.ListUserPermissionsByEmail(ctx, listPermissionsUserEmail)
	if err != nil {
		return fmt.Errorf("failed to list user permissions: %w", err)
	}

	if len(permissions) == 0 {
		fmt.Printf("No permissions found for user '%s'\n", listPermissionsUserEmail)
		return nil
	}

	fmt.Printf("Permissions for user '%s':\n", listPermissionsUserEmail)

	// Group permissions by resource
	resourceMap := make(map[string][]interface{})
	for _, perm := range permissions {
		resourceMap["permissions"] = append(resourceMap["permissions"], perm)
	}

	for _, perm := range permissions {
		fmt.Printf("  - Permission: %+v\n", perm)
	}

	return nil
}
