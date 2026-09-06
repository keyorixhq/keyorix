package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	createName        string
	createDescription string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a group",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createName, "name", "", "Group name (required)")
	createCmd.Flags().StringVar(&createDescription, "description", "", "Description")
}

// groupAPIResponse mirrors server/http/handlers/groups_handler.go's
// groupToAPIResponse -- the {"id","name","description"} shape returned by
// GET/POST/PUT /api/v1/groups(/{id}). Shared by create/get/list/update.
type groupAPIResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createName == "" {
		return errors.New("name is required (use --name)")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		fmt.Printf("Creating group %q on %s...\n", createName, rc.Endpoint)
		body := map[string]string{"name": createName, "description": createDescription}
		var out groupAPIResponse
		if err := rc.Post(ctx, "/api/v1/groups", body, &out); err != nil {
			return fmt.Errorf("failed to create group: %w", err)
		}
		fmt.Printf("Group created: id=%d name=%s\n", out.ID, out.Name)
		return nil
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	g, err := service.CreateGroup(ctx, common.ResolveActorID(), &core.CreateGroupRequest{
		Name:        createName,
		Description: createDescription,
	})
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	fmt.Printf("Group created: id=%d name=%s\n", g.ID, g.Name)
	return nil
}
