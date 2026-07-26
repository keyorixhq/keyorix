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
	addMemberGroupID   uint
	addMemberUserID    uint
	addMemberProjectID uint
)

var addMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a user to a group",
	RunE:  runAddMember,
}

func init() {
	addMemberCmd.Flags().UintVar(&addMemberGroupID, "group-id", 0, "Group ID (required)")
	addMemberCmd.Flags().UintVar(&addMemberUserID, "user-id", 0, "User ID (required)")
	addMemberCmd.Flags().UintVar(&addMemberProjectID, "project", 0, "scope membership to a project (0 = global)")
}

func runAddMember(cmd *cobra.Command, args []string) error {
	if addMemberGroupID == 0 || addMemberUserID == 0 {
		return errors.New("--group-id and --user-id are required")
	}

	ctx := context.Background()

	if c, ok := common.NewRemoteClient(); ok {
		path := "/api/v1/groups/" + strconv.FormatUint(uint64(addMemberGroupID), 10) + "/members"
		body := map[string]uint{"user_id": addMemberUserID, "project_id": addMemberProjectID}
		var out interface{}
		if err := c.Post(ctx, path, body, &out); err != nil {
			return fmt.Errorf("failed to add member: %w", err)
		}
		fmt.Printf("User %d added to group %d (project %d).\n", addMemberUserID, addMemberGroupID, addMemberProjectID)
		return nil
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	if err := service.AddUserToGroup(ctx, common.ResolveActorID(), addMemberUserID, addMemberGroupID, addMemberProjectID); err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}
	fmt.Printf("User %d added to group %d (project %d).\n", addMemberUserID, addMemberGroupID, addMemberProjectID)
	return nil
}
