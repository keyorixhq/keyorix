package share

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	listSecretID uint
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List shares for a secret",
	RunE:  runList,
}

func init() {
	listCmd.Flags().UintVar(&listSecretID, "secret-id", 0, "Secret ID (required)")
	listCmd.MarkFlagRequired("secret-id") // #nosec G104
}

func runList(cmd *cobra.Command, args []string) error {
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

	// Call service
	ctx := context.Background()
	shares, err := service.ListSecretShares(ctx, listSecretID)
	if err != nil {
		return fmt.Errorf("failed to list shares: %w", err)
	}

	// Print result
	if len(shares) == 0 {
		fmt.Println("No shares found for this secret.")
		return nil
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSECRET ID\tOWNER ID\tRECIPIENT ID\tIS GROUP\tPERMISSION\tCREATED AT")
	for _, share := range shares {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%t\t%s\t%s\n",
			share.ID,
			share.SecretID,
			share.OwnerID,
			share.RecipientID,
			share.IsGroup,
			share.Permission,
			share.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	w.Flush() // #nosec G104

	return nil
}
