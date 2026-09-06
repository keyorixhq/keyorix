package group

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	updateGroupID          uint
	updateGroupName        string
	updateGroupDescription string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a group",
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().UintVar(&updateGroupID, "id", 0, "Group ID (required)")
	updateCmd.Flags().StringVar(&updateGroupName, "name", "", "New name")
	updateCmd.Flags().StringVar(&updateGroupDescription, "description", "", "New description")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	if updateGroupID == 0 {
		return errors.New("group id is required (use --id)")
	}
	if updateGroupName == "" && updateGroupDescription == "" {
		return errors.New("provide at least one of --name or --description")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		fmt.Printf("Updating group %d on %s...\n", updateGroupID, rc.Endpoint)
		path := "/api/v1/groups/" + strconv.FormatUint(uint64(updateGroupID), 10)
		body := map[string]string{"name": updateGroupName, "description": updateGroupDescription}
		var out groupAPIResponse
		if err := rc.Put(ctx, path, body, &out); err != nil {
			return fmt.Errorf("failed to update group: %w", err)
		}
		fmt.Printf("Group updated: id=%d name=%s\n", out.ID, out.Name)
		return nil
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	g, err := service.UpdateGroup(ctx, common.ResolveActorID(), &core.UpdateGroupRequest{
		ID:          updateGroupID,
		Name:        updateGroupName,
		Description: updateGroupDescription,
	})
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	fmt.Printf("Group updated: id=%d name=%s\n", g.ID, g.Name)
	return nil
}
