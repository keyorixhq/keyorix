package project

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	createName        string
	createDescription string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new project",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createName, "name", "", "Project name (required)")
	createCmd.Flags().StringVar(&createDescription, "description", "", "Project description")
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createName == "" {
		return fmt.Errorf("--name is required")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		body := map[string]interface{}{
			"name":        createName,
			"description": createDescription,
		}
		var project models.Project
		if err := rc.Post(ctx, "/api/v1/projects", body, &project); err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}
		fmt.Printf("Project created: id=%d name=%q\n", project.ID, project.Name)
		fmt.Println("Default environments (development, staging, production) have been seeded.")
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	project, err := svc.CreateProject(ctx, createName, createDescription)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	fmt.Printf("Project created: id=%d name=%q\n", project.ID, project.Name)
	fmt.Println("Default environments (development, staging, production) have been seeded.")
	return nil
}
