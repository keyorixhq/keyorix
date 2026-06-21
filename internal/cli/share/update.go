package share

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
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

	_ = updateCmd.MarkFlagRequired("share-id")   // #nosec G104
	_ = updateCmd.MarkFlagRequired("permission") // #nosec G104
}

func runUpdate(cmd *cobra.Command, args []string) error {
	// Validate permission
	if updatePermission != "read" && updatePermission != "write" { //nolint:goconst
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", updatePermission)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

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
