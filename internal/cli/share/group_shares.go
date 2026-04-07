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
	groupSharesGroupID uint
)

var groupSharesCmd = &cobra.Command{
	Use:   "group-shares",
	Short: "List shares for a group",
	RunE:  runGroupShares,
}

func init() {
	groupSharesCmd.Flags().UintVar(&groupSharesGroupID, "group-id", 0, "Group ID (required)")
	groupSharesCmd.MarkFlagRequired("group-id")
	
	// Add to parent command
	ShareCmd.AddCommand(groupSharesCmd)
}

func runGroupShares(cmd *cobra.Command, args []string) error {
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

	// Call service
	ctx := context.Background()
	shares, err := service.ListGroupShares(ctx, groupSharesGroupID)
	if err != nil {
		return fmt.Errorf("failed to list group shares: %w", err)
	}

	// Print result
	if len(shares) == 0 {
		fmt.Println("No shares found for this group.")
		return nil
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSECRET ID\tOWNER ID\tGROUP ID\tPERMISSION\tCREATED AT")
	for _, share := range shares {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%s\t%s\n",
			share.ID,
			share.SecretID,
			share.OwnerID,
			share.RecipientID,
			share.Permission,
			share.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	w.Flush()

	return nil
}