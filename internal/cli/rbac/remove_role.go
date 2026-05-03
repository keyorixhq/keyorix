package rbac

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var removeRoleCmd = &cobra.Command{
	Use:   "remove-role",
	Short: "Remove a role from a user",
	Long:  "Remove a role assignment from a user by email address",
	RunE:  runRemoveRole,
}

var (
	removeUserEmail string
	removeRoleName  string
)

func init() {
	removeRoleCmd.Flags().StringVar(&removeUserEmail, "user", "", "User email address (required)")
	removeRoleCmd.Flags().StringVar(&removeRoleName, "role", "", "Role name to remove (required)")

	_ = removeRoleCmd.MarkFlagRequired("user")
	_ = removeRoleCmd.MarkFlagRequired("role")
}

func runRemoveRole(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize database
	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create storage layer
	storage := store.NewLocalStorage(db)

	// Create core service
	coreService := core.NewKeyorixCore(storage)

	// Use core service to remove role
	ctx := context.Background()
	err = coreService.RemoveRoleFromUser(ctx, removeUserEmail, removeRoleName)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	fmt.Printf("✅ Successfully removed role '%s' from user '%s'\n", removeRoleName, removeUserEmail)
	return nil
}
