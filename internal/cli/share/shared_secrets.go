package share

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	sharedSecretsUserID uint
)

var sharedSecretsCmd = &cobra.Command{
	Use:   "shared-secrets",
	Short: "List secrets shared with a user",
	RunE:  runSharedSecrets,
}

func init() {
	sharedSecretsCmd.Flags().UintVar(&sharedSecretsUserID, "user-id", 0, "User ID (required)")
	sharedSecretsCmd.MarkFlagRequired("user-id") // #nosec G104
}

func runSharedSecrets(cmd *cobra.Command, args []string) error {
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
	storage := local.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	// Call service
	ctx := context.Background()
	secrets, err := service.ListSharedSecrets(ctx, sharedSecretsUserID)
	if err != nil {
		return fmt.Errorf("failed to list shared secrets: %w", err)
	}

	// Print result
	if len(secrets) == 0 {
		fmt.Println("No shared secrets found for this user.")
		return nil
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tNAMESPACE\tZONE\tENVIRONMENT\tCREATED BY\tCREATED AT")
	for _, secret := range secrets {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n",
			secret.ID,
			secret.Name,
			secret.Type,
			secret.NamespaceID,
			secret.ZoneID,
			secret.EnvironmentID,
			secret.CreatedBy,
			secret.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	w.Flush() // #nosec G104

	return nil
}
