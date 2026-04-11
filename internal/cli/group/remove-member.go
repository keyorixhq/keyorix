package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	removeMemberGroupID uint
	removeMemberUserID  uint
)

var removeMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a user from a group",
	RunE:  runRemoveMember,
}

func init() {
	removeMemberCmd.Flags().UintVar(&removeMemberGroupID, "group-id", 0, "Group ID (required)")
	removeMemberCmd.Flags().UintVar(&removeMemberUserID, "user-id", 0, "User ID (required)")
}

func runRemoveMember(cmd *cobra.Command, args []string) error {
	if removeMemberGroupID == 0 || removeMemberUserID == 0 {
		return errors.New("--group-id and --user-id are required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
	if err := service.RemoveUserFromGroup(ctx, removeMemberUserID, removeMemberGroupID); err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	fmt.Printf("User %d removed from group %d.\n", removeMemberUserID, removeMemberGroupID)
	return nil
}
