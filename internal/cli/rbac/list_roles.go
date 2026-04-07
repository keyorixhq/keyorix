package rbac

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var listRolesCmd = &cobra.Command{
	Use:   "list-roles",
	Short: "List all available roles",
	Long:  "List all roles in the system",
	RunE:  runListRoles,
}

func runListRoles(cmd *cobra.Command, args []string) error {
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

	// Initialize storage
	storage := local.NewLocalStorage(db)

	// Create context
	ctx := context.Background()

	// TODO: Implement ListRoles in core service
	// For now, use storage directly
	roles, err := storage.ListRoles(ctx)
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
	}

	if len(roles) == 0 {
		fmt.Println("No roles found")
		return nil
	}

	fmt.Println("Available roles:")
	for _, role := range roles {
		fmt.Printf("  - %s: %s\n", role.Name, role.Description)
	}

	return nil
}
