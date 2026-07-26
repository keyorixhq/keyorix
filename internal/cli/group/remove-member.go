package group

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	removeMemberGroupID   uint
	removeMemberUserID    uint
	removeMemberProjectID uint
)

var removeMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a user from a group",
	RunE:  runRemoveMember,
}

func init() {
	removeMemberCmd.Flags().UintVar(&removeMemberGroupID, "group-id", 0, "Group ID (required)")
	removeMemberCmd.Flags().UintVar(&removeMemberUserID, "user-id", 0, "User ID (required)")
	removeMemberCmd.Flags().UintVar(&removeMemberProjectID, "project", 0, "scope membership to a project (0 = global)")
}

func runRemoveMember(cmd *cobra.Command, args []string) error {
	if removeMemberGroupID == 0 || removeMemberUserID == 0 {
		return errors.New("--group-id and --user-id are required")
	}

	ctx := context.Background()

	if c, ok := common.NewRemoteClient(); ok {
		path := "/api/v1/groups/" + strconv.FormatUint(uint64(removeMemberGroupID), 10) +
			"/members/" + strconv.FormatUint(uint64(removeMemberUserID), 10)
		if removeMemberProjectID != 0 {
			path += "?project_id=" + strconv.FormatUint(uint64(removeMemberProjectID), 10)
		}
		if err := c.Delete(ctx, path); err != nil {
			return fmt.Errorf("failed to remove member: %w", err)
		}
		fmt.Printf("User %d removed from group %d (project %d).\n", removeMemberUserID, removeMemberGroupID, removeMemberProjectID)
		return nil
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	if err := service.RemoveUserFromGroup(ctx, common.ResolveActorID(), removeMemberUserID, removeMemberGroupID, removeMemberProjectID); err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	fmt.Printf("User %d removed from group %d (project %d).\n", removeMemberUserID, removeMemberGroupID, removeMemberProjectID)
	return nil
}
