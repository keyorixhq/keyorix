package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var checkPermissionCmd = &cobra.Command{
	Use:   "check-permission",
	Short: "Check if a user has a specific permission",
	Long:  "Check if a user has a specific permission by email address and permission name",
	RunE:  runCheckPermission,
}

var (
	checkUserEmail      string
	checkPermissionName string
)

func init() {
	checkPermissionCmd.Flags().StringVar(&checkUserEmail, "user", "", "User email address (required)")
	checkPermissionCmd.Flags().StringVar(&checkPermissionName, "permission", "", "Permission name to check (required)")

	_ = checkPermissionCmd.MarkFlagRequired("user")
	_ = checkPermissionCmd.MarkFlagRequired("permission")
}

func runCheckPermission(cmd *cobra.Command, args []string) error {
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

	// Permissions are named "resource.action" (e.g. secrets.read, system.admin).
	resource, action, perr := splitPermissionName(checkPermissionName)
	if perr != nil {
		return perr
	}

	hasPermission, err := service.HasPermissionByEmail(ctx, checkUserEmail, resource, action)
	if err != nil {
		return fmt.Errorf("failed to check permission: %w", err)
	}

	if hasPermission {
		fmt.Printf("✅ User '%s' has permission '%s'\n", checkUserEmail, checkPermissionName)
	} else {
		fmt.Printf("❌ User '%s' does NOT have permission '%s'\n", checkUserEmail, checkPermissionName)
	}

	return nil
}

// splitPermissionName parses a "resource.action" permission name into its parts.
func splitPermissionName(name string) (resource, action string, err error) {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("permission must be in 'resource.action' form (e.g. secrets.read), got %q", name)
	}
	return parts[0], parts[1], nil
}
