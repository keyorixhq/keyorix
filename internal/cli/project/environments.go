package project

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var environmentsCmd = &cobra.Command{
	Use:   "environments <project-id>",
	Short: "List environments for a project",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvironments,
}

func runEnvironments(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid project ID: %s", args[0])
	}
	projectID := uint(id)
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		// rc.Get already strips the {"data":…} envelope — decode the inner payload directly.
		var resp struct {
			Environments []*models.Environment `json:"environments"`
		}
		path := fmt.Sprintf("/api/v1/projects/%d/environments", projectID)
		if err := rc.Get(ctx, path, &resp); err != nil {
			return fmt.Errorf("failed to list environments: %w", err)
		}
		printEnvironments(resp.Environments, projectID)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	envs, err := svc.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to list environments: %w", err)
	}
	printEnvironments(envs, projectID)
	return nil
}

func printEnvironments(envs []*models.Environment, projectID uint) {
	if len(envs) == 0 {
		fmt.Printf("No environments found for project %d.\n", projectID)
		return
	}
	fmt.Printf("Environments for project %d:\n", projectID)
	fmt.Printf("%-5s %s\n", "ID", "NAME")
	fmt.Printf("%-5s %s\n", "-----", "--------------------")
	for _, e := range envs {
		fmt.Printf("%-5d %s\n", e.ID, e.Name)
	}
}
