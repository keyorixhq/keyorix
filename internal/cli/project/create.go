package project

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	createName        string
	createDescription string
	createEnvs        string // comma-separated env names; empty = use defaults
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new project",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createName, "name", "", "Project name (required)")
	createCmd.Flags().StringVar(&createDescription, "description", "", "Project description")
	createCmd.Flags().StringVar(&createEnvs, "envs", "",
		`Comma-separated environment names to seed (default: "development,staging,production")`)
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createName == "" {
		return fmt.Errorf("--name is required")
	}
	ctx := context.Background()

	body := map[string]interface{}{
		"name":        createName,
		"description": createDescription,
	}
	if createEnvs != "" {
		envList := splitEnvNames(createEnvs)
		if len(envList) == 0 {
			return fmt.Errorf("--envs must not be empty")
		}
		// Field name must match the server's CreateProject handler ("environments");
		// it previously sent "envs", which the server ignored — so --envs was silently
		// dropped in remote mode and the project got the default environment set.
		body["environments"] = envList
	}

	if rc, ok := common.NewRemoteClient(); ok {
		var project models.Project
		if err := rc.Post(ctx, "/api/v1/projects", body, &project); err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}
		printCreateResult(project.ID, project.Name, createEnvs)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	var project *models.Project
	if createEnvs != "" {
		envList := splitEnvNames(createEnvs)
		var createErr error
		project, createErr = svc.CreateProjectWithEnvs(ctx, createName, createDescription, envList)
		if createErr != nil {
			return fmt.Errorf("failed to create project: %w", createErr)
		}
	} else {
		var createErr error
		project, createErr = svc.CreateProject(ctx, createName, createDescription)
		if createErr != nil {
			return fmt.Errorf("failed to create project: %w", createErr)
		}
	}
	printCreateResult(project.ID, project.Name, createEnvs)
	return nil
}

func splitEnvNames(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func printCreateResult(id uint, name, envsFlag string) {
	fmt.Printf("Project created: id=%d name=%q\n", id, name)
	if envsFlag != "" {
		fmt.Printf("Environments seeded: %s\n", envsFlag)
	} else {
		fmt.Println("Default environments (development, staging, production) have been seeded.")
	}
}
