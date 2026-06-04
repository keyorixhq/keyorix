package invite

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	revokeID uint
	revokeBy string
)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a pending invitation",
	Long:  "Cancel a pending project invitation by ID (ADR-024).",
	RunE:  runRevoke,
}

func init() {
	revokeCmd.Flags().UintVar(&revokeID, "id", 0, "Invitation ID (required)")
	revokeCmd.Flags().StringVar(&revokeBy, "by", "", "Revoker email address (required, for audit)")
	_ = revokeCmd.MarkFlagRequired("id")
	_ = revokeCmd.MarkFlagRequired("by")
}

func runRevoke(cmd *cobra.Command, args []string) error {
	if revokeID == 0 {
		return fmt.Errorf("--id is required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	actorID, err := resolveUserID(ctx, service, revokeBy)
	if err != nil {
		return err
	}
	if err := service.RevokeInvitation(ctx, revokeID, actorID); err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}
	fmt.Printf("Invitation %d revoked.\n", revokeID)
	return nil
}
