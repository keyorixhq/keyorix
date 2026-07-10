// use.go — keyorix project use <name>
// Writes active_project to ~/.keyorix/cli.yaml (ADR-016).
package project

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/spf13/cobra"
)

var useCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the active project for subsequent commands",
	Long: `Saves the active project name to ~/.keyorix/cli.yaml.
All project-scoped commands inherit this context; override per-command with --project.`,
	Args: cobra.ExactArgs(1),
	RunE: runUse,
}

func runUse(cmd *cobra.Command, args []string) error {
	name := args[0]
	ctx := context.Background()

	// Validate the project exists (remote or local).
	if rc, ok := common.NewRemoteClient(); ok {
		// rc.Get already strips the {"data":…} envelope — decode the inner payload directly.
		var resp struct {
			Projects []struct {
				Name string `json:"name"`
			} `json:"projects"`
		}
		if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}
		found := false
		for _, p := range resp.Projects {
			if p.Name == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("project %q not found — run 'keyorix project list' to see available projects", name)
		}
	} else {
		svc, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		projects, err := svc.ListProjects(ctx)
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}
		found := false
		for _, p := range projects {
			if p.Name == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("project %q not found — run 'keyorix project list' to see available projects", name)
		}
	}

	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		cfg = cliconfig.DefaultCLIConfig()
	}
	cfg.SetActiveProject(name)
	if err := cliconfig.SaveCLIConfig(cfg, ""); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Printf("Active project set to %q\n", name)
	fmt.Println("All project-scoped commands will now use this project by default.")
	return nil
}
