// env.go — keyorix project env list/create/delete
// Environment management commands scoped to a project (ADR-017).
package project

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

const (
	descOverrideProject = "Override the active project"
)

// envCmd is the parent command: keyorix project env
var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage environments within a project",
}

var envProjectFlag string

// --- env list ---

var envListCmd = &cobra.Command{
	Use:   "list",
	Short: "List environments for the active (or specified) project",
	RunE:  runEnvList,
}

func runEnvList(cmd *cobra.Command, args []string) error {
	name, projectID, err := resolveProjectContext(envProjectFlag)
	if err != nil {
		return err
	}
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
		printEnvironmentTable(resp.Environments, name)
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
	printEnvironmentTable(envs, name)
	return nil
}

// --- env create ---

var envCreateName string

var envCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new environment in the active (or specified) project",
	RunE:  runEnvCreate,
}

func init() {
	envCreateCmd.Flags().StringVar(&envCreateName, "name", "", "Environment name (required)")
	_ = envCreateCmd.MarkFlagRequired("name")
	envListCmd.Flags().StringVar(&envProjectFlag, "project", "", descOverrideProject)
	envCreateCmd.Flags().StringVar(&envProjectFlag, "project", "", descOverrideProject)
	envDeleteCmd.Flags().StringVar(&envProjectFlag, "project", "", descOverrideProject)
	envDeleteCmd.Flags().BoolVar(&envDeleteConfirm, "confirm", false, "Confirm deletion without interactive prompt")
}

func runEnvCreate(cmd *cobra.Command, args []string) error {
	_, projectID, err := resolveProjectContext(envProjectFlag)
	if err != nil {
		return err
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		body := map[string]interface{}{"name": envCreateName}
		var env models.Environment
		path := fmt.Sprintf("/api/v1/projects/%d/environments", projectID)
		if err := rc.Post(ctx, path, body, &env); err != nil {
			return fmt.Errorf("failed to create environment: %w", err)
		}
		fmt.Printf("Environment %q created (id=%d)\n", env.Name, env.ID)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	env, err := svc.CreateEnvironment(ctx, projectID, envCreateName)
	if err != nil {
		return fmt.Errorf("failed to create environment: %w", err)
	}
	fmt.Printf("Environment %q created (id=%d)\n", env.Name, env.ID)
	return nil
}

// --- env delete ---

var envDeleteConfirm bool

var envDeleteCmd = &cobra.Command{
	Use:   "delete <env-id>",
	Short: "Delete an environment by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvDelete,
}

func runEnvDelete(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid environment ID: %s", args[0])
	}

	// Deleting an environment (and everything scoped to it) is irreversible, so
	// require an explicit --confirm — mirrors `notification channel delete`.
	if !envDeleteConfirm {
		return fmt.Errorf("add --confirm to confirm deletion of environment %d", id)
	}

	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		path := fmt.Sprintf("/api/v1/environments/%d", id)
		if err := rc.Delete(ctx, path); err != nil {
			return fmt.Errorf("failed to delete environment: %w", err)
		}
		fmt.Printf("Environment %d deleted\n", id)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	if err := svc.DeleteEnvironment(ctx, uint(id)); err != nil {
		return fmt.Errorf("failed to delete environment: %w", err)
	}
	fmt.Printf("Environment %d deleted\n", id)
	return nil
}

// --- helpers ---

// resolveProjectContext looks up the project by name (from flag or active context)
// and returns the name and numeric ID.
func resolveProjectContext(flagValue string) (string, uint, error) {
	name, err := common.ResolveProject(flagValue)
	if err != nil {
		return "", 0, err
	}
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		// rc.Get already strips the {"data":…} envelope — decode the inner payload directly.
		var resp struct {
			Projects []struct {
				ID   uint   `json:"id"`
				Name string `json:"name"`
			} `json:"projects"`
		}
		if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
			return "", 0, fmt.Errorf("failed to list projects: %w", err)
		}
		for _, p := range resp.Projects {
			if p.Name == name {
				return name, p.ID, nil
			}
		}
		return "", 0, fmt.Errorf("project %q not found", name)
	}
	svc, err := common.InitializeCoreService()
	if err != nil {
		return "", 0, fmt.Errorf("failed to initialize service: %w", err)
	}
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range projects {
		if p.Name == name {
			return name, p.ID, nil
		}
	}
	return "", 0, fmt.Errorf("project %q not found", name)
}

func printEnvironmentTable(envs []*models.Environment, projectName string) {
	if len(envs) == 0 {
		fmt.Printf("No environments found for project %q.\n", projectName)
		return
	}
	fmt.Printf("Environments for project %q:\n", projectName)
	fmt.Printf("%-5s %s\n", "ID", "NAME")
	fmt.Printf("%-5s %s\n", "-----", "--------------------")
	for _, e := range envs {
		fmt.Printf("%-5d %s\n", e.ID, e.Name)
	}
}
