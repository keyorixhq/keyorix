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

func runCreate(cmd *cobra.Command, args []string) error {
	if createName == "" {
		return errors.New("name is required (use --name)")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()
	g, err := service.CreateGroup(ctx, &core.CreateGroupRequest{
		Name:        createName,
		Description: createDescription,
	})
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	fmt.Printf("Group created: id=%d name=%s\n", g.ID, g.Name)
	return nil
}
