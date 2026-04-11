package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var deleteGroupID uint

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a group",
	RunE:  runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteGroupID, "id", 0, "Group ID (required)")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteGroupID == 0 {
		return errors.New("group id is required (use --id)")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
	if err := service.DeleteGroup(ctx, deleteGroupID); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	fmt.Printf("Group %d deleted.\n", deleteGroupID)
	return nil
}
