package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var membersGroupID uint

var membersCmd = &cobra.Command{
	Use:   "members",
	Short: "List members of a group",
	RunE:  runMembers,
}

func init() {
	membersCmd.Flags().UintVar(&membersGroupID, "id", 0, "Group ID (required)")
}

func runMembers(cmd *cobra.Command, args []string) error {
	if membersGroupID == 0 {
		return errors.New("group id is required (use --id)")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
	members, err := service.GetGroupMembers(ctx, membersGroupID)
	if err != nil {
		return fmt.Errorf("failed to list members: %w", err)
	}
	fmt.Printf("Group %d — %d member(s)\n", membersGroupID, len(members))
	fmt.Printf("%-6s %-20s %-30s\n", "ID", "USERNAME", "EMAIL")
	for _, u := range members {
		fmt.Printf("%-6d %-20s %-30s\n", u.ID, u.Username, u.Email)
	}
	return nil
}
