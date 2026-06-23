package share

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	createSecretID    uint
	createRecipientID uint
	createIsGroup     bool
	createPermission  string
	createExpires     string
	createTTL         string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Share a secret with another user or group",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().UintVar(&createSecretID, "secret-id", 0, "Secret ID (required)")
	createCmd.Flags().UintVar(&createRecipientID, "recipient-id", 0, "Recipient ID (required)")
	createCmd.Flags().BoolVar(&createIsGroup, "is-group", false, "Whether the recipient is a group")
	createCmd.Flags().StringVar(&createPermission, "permission", "read", "Permission level (read or write)")
	createCmd.Flags().StringVar(&createExpires, "expires", "", "Make the share time-bound: absolute expiry (RFC3339, e.g. 2026-07-01T15:00:00Z)")
	createCmd.Flags().StringVar(&createTTL, "ttl", "", "Make the share time-bound: lifetime from now (Go duration, e.g. 24h, 30m); mutually exclusive with --expires")

	_ = createCmd.MarkFlagRequired("secret-id")    // #nosec G104
	_ = createCmd.MarkFlagRequired("recipient-id") // #nosec G104
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Validate permission
	if createPermission != "read" && createPermission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", createPermission)
	}

	// Resolve the optional time-bound expiry (nil = permanent share).
	expiresAt, err := resolveShareExpiry(createExpires, createTTL)
	if err != nil {
		return err
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// Create context
	ctx := context.Background()

	var shareRecord *models.ShareRecord

	// Handle group sharing differently
	if createIsGroup {
		// Create group share request
		req := &core.GroupShareSecretRequest{
			SecretID:   createSecretID,
			GroupID:    createRecipientID,
			Permission: createPermission,
			SharedBy:   1, // CLI user ID
			ExpiresAt:  expiresAt,
		}

		// Call service for group sharing
		shareRecord, err = service.ShareSecretWithGroup(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to share secret with group: %w", err)
		}
	} else {
		// Create user share request
		req := &core.ShareSecretRequest{
			SecretID:    createSecretID,
			RecipientID: createRecipientID,
			IsGroup:     false,
			Permission:  createPermission,
			SharedBy:    1, // CLI user ID
			ExpiresAt:   expiresAt,
		}

		// Call service for user sharing
		shareRecord, err = service.ShareSecret(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to share secret with user: %w", err)
		}
	}

	// Print result
	fmt.Printf("✅ Secret shared successfully!\n")
	fmt.Printf("Share ID: %d\n", shareRecord.ID)
	fmt.Printf("Secret ID: %d\n", shareRecord.SecretID)
	fmt.Printf("Owner ID: %d\n", shareRecord.OwnerID)
	fmt.Printf("Recipient ID: %d\n", shareRecord.RecipientID)
	fmt.Printf("Is Group: %t\n", shareRecord.IsGroup)
	fmt.Printf("Permission: %s\n", shareRecord.Permission)
	fmt.Printf("Created At: %s\n", shareRecord.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expires At: %s\n", formatShareExpiry(shareRecord.ExpiresAt))

	return nil
}
