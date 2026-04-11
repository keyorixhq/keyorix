package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	addMemberGroupID uint
	addMemberUserID  uint
)

var addMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a user to a group",
	RunE:  runAddMember,
}

func init() {
	addMemberCmd.Flags().UintVar(&addMemberGroupID, "group-id", 0, "Group ID (required)")
	addMemberCmd.Flags().UintVar(&addMemberUserID, "user-id", 0, "User ID (required)")
}

func runAddMember(cmd *cobra.Command, args []string) error {
	if addMemberGroupID == 0 || addMemberUserID == 0 {
		return errors.New("--group-id and --user-id are required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
	if err := service.AddUserToGroup(ctx, addMemberUserID, addMemberGroupID); err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}
	fmt.Printf("User %d added to group %d.\n", addMemberUserID, addMemberGroupID)
	return nil
}
