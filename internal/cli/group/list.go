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

func runList(cmd *cobra.Command, args []string) error {
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
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
