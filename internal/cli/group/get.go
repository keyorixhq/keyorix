package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var getGroupID uint

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a group by id",
	RunE:  runGet,
}

func init() {
	getCmd.Flags().UintVar(&getGroupID, "id", 0, "Group ID (required)")
}

func runGet(cmd *cobra.Command, args []string) error {
	if getGroupID == 0 {
		return errors.New("group id is required (use --id)")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
	g, err := service.GetGroup(ctx, getGroupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	fmt.Printf("ID: %d\nName: %s\nDescription: %s\n", g.ID, g.Name, g.Description)
	return nil
}
