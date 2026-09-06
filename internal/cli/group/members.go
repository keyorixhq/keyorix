package group

import (
	"context"
	"errors"
	"fmt"
	"strconv"

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

// groupMemberAPIResponse is the subset of userToAPIResponse's fields
// (server/http/handlers/users_handler.go) this command displays.
type groupMemberAPIResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// listGroupMembersAPIResponse mirrors GET /api/v1/groups/{id}/members's
// {"members": [...], "total": N} envelope (groups_members.go's GetGroupMembers).
type listGroupMembersAPIResponse struct {
	Members []groupMemberAPIResponse `json:"members"`
	Total   int                      `json:"total"`
}

func runMembers(cmd *cobra.Command, args []string) error {
	if membersGroupID == 0 {
		return errors.New("group id is required (use --id)")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		path := "/api/v1/groups/" + strconv.FormatUint(uint64(membersGroupID), 10) + "/members"
		var out listGroupMembersAPIResponse
		if err := rc.Get(ctx, path, &out); err != nil {
			return fmt.Errorf("failed to list members: %w", err)
		}
		fmt.Printf("Group %d — %d member(s)\n", membersGroupID, len(out.Members))
		fmt.Printf("%-6s %-20s %-30s\n", "ID", "USERNAME", "EMAIL")
		for _, u := range out.Members {
			fmt.Printf("%-6d %-20s %-30s\n", u.ID, u.Username, u.Email)
		}
		return nil
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
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
