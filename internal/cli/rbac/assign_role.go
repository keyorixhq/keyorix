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

var assignRoleCmd = &cobra.Command{
	Use:   "assign-role",
	Short: "Assign a role to a user",
	Long:  "Assign a role to a user by email address",
	RunE:  runAssignRole,
}

var (
	userEmail string
	roleName  string
)

func init() {
	assignRoleCmd.Flags().StringVar(&userEmail, "user", "", "User email address (required)")
	assignRoleCmd.Flags().StringVar(&roleName, "role", "", "Role name to assign (required)")

	_ = assignRoleCmd.MarkFlagRequired("user")
	_ = assignRoleCmd.MarkFlagRequired("role")
}

func runAssignRole(cmd *cobra.Command, args []string) error {
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

	// Use core service to assign role
	ctx := context.Background()
	err = coreService.AssignRoleToUser(ctx, userEmail, roleName)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	fmt.Printf("✅ Successfully assigned role '%s' to user '%s'\n", roleName, userEmail)
	return nil
}
