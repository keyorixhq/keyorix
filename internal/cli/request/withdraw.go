package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	withdrawID   uint
	withdrawUser string
)

var withdrawCmd = &cobra.Command{
	Use:   "withdraw",
	Short: "Withdraw your own pending access request",
	Long:  "Cancel a pending access request you own, by ID (self-service, ADR-024).",
	RunE:  runWithdraw,
}

func init() {
	withdrawCmd.Flags().UintVar(&withdrawID, "id", 0, "Access request ID (required)")
	withdrawCmd.Flags().StringVar(&withdrawUser, "user", "", "Requester email address (required — must own the request)")
	_ = withdrawCmd.MarkFlagRequired("id")
	_ = withdrawCmd.MarkFlagRequired("user")
}

func runWithdraw(cmd *cobra.Command, args []string) error {
	if withdrawID == 0 {
		return fmt.Errorf("--id is required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	userID, err := resolveUserID(ctx, service, withdrawUser)
	if err != nil {
		return err
	}
	if err := service.WithdrawAccessRequest(ctx, withdrawID, userID); err != nil {
		return fmt.Errorf("failed to withdraw access request: %w", err)
	}
	fmt.Printf("Access request %d withdrawn.\n", withdrawID)
	return nil
}
