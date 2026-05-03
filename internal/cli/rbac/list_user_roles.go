package rbac

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

var listUserRolesCmd = &cobra.Command{
	Use:   "list-user-roles",
	Short: "List roles assigned to a user",
	Long:  "List all roles assigned to a specific user by email address",
	RunE:  runListUserRoles,
}

var listUserEmail string

func init() {
	listUserRolesCmd.Flags().StringVar(&listUserEmail, "user", "", "User email address (required)")
	_ = listUserRolesCmd.MarkFlagRequired("user")
}

func runListUserRoles(cmd *cobra.Command, args []string) error {
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
	storage := store.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	// Create context
	ctx := context.Background()

	roles, err := service.ListUserRolesByEmail(ctx, listUserEmail)
	if err != nil {
		return fmt.Errorf("failed to list user roles: %w", err)
	}

	if len(roles) == 0 {
		fmt.Printf("No roles assigned to user '%s'\n", listUserEmail)
		return nil
	}

	fmt.Printf("Roles assigned to user '%s':\n", listUserEmail)
	for _, role := range roles {
		fmt.Printf("  - %s: %s\n", role.Name, role.Description)
	}

	return nil
}
