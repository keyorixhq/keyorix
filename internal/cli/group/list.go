package group

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups",
	RunE:  runList,
}

// listGroupsAPIResponse mirrors GET /api/v1/groups's {"groups": [...], "total": N}
// envelope (server/http/handlers/groups_handler.go's ListGroups).
type listGroupsAPIResponse struct {
	Groups []groupAPIResponse `json:"groups"`
	Total  int                `json:"total"`
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		var out listGroupsAPIResponse
		if err := rc.Get(ctx, "/api/v1/groups", &out); err != nil {
			return fmt.Errorf("failed to list groups: %w", err)
		}
		fmt.Printf("%-6s %-25s %s\n", "ID", "NAME", "DESCRIPTION")
		for _, g := range out.Groups {
			fmt.Printf("%-6d %-25s %s\n", g.ID, g.Name, g.Description)
		}
		return nil
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	groups, err := service.ListGroups(ctx)
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}
	fmt.Printf("%-6s %-25s %s\n", "ID", "NAME", "DESCRIPTION")
	for _, g := range groups {
		fmt.Printf("%-6d %-25s %s\n", g.ID, g.Name, g.Description)
	}
	return nil
}
