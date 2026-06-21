package share

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	revokeShareID uint
)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a share",
	RunE:  runRevoke,
}

func init() {
	revokeCmd.Flags().UintVar(&revokeShareID, "share-id", 0, "Share ID (required)")
	_ = revokeCmd.MarkFlagRequired("share-id") // #nosec G104
}

func runRevoke(cmd *cobra.Command, args []string) error {
	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// Call service
	ctx := context.Background()
	err = service.RevokeShare(ctx, revokeShareID, 1) // CLI user ID
	if err != nil {
		return fmt.Errorf("failed to revoke share: %w", err)
	}

	// Print result
	fmt.Printf("✅ Share revoked successfully!\n")
	fmt.Printf("Share ID: %d\n", revokeShareID)

	return nil
}
