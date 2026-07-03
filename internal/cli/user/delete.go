package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	deleteUserID uint
	deleteBy     string
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE:  runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteUserID, "id", 0, "User ID (required)")
	deleteCmd.Flags().StringVar(&deleteBy, "by", "", "Acting admin email (required, for audit)")
	_ = deleteCmd.MarkFlagRequired("id")
	_ = deleteCmd.MarkFlagRequired("by")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteUserID == 0 {
		return errors.New("user id is required (use --id)")
	}
	if deleteBy == "" {
		return errors.New("acting admin email is required (use --by)")
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	adminID, err := resolveAdminID(ctx, service, deleteBy)
	if err != nil {
		return err
	}

	if err := service.DeleteUser(ctx, adminID, deleteUserID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	fmt.Printf("User %d deleted.\n", deleteUserID)
	return nil
}
