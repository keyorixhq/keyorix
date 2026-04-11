package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var deleteUserID uint

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE:  runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteUserID, "id", 0, "User ID (required)")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteUserID == 0 {
		return errors.New("user id is required (use --id)")
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	if err := service.DeleteUser(ctx, deleteUserID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	fmt.Printf("User %d deleted.\n", deleteUserID)
	return nil
}
