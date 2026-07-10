package project

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all projects",
	RunE:  runList,
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		// rc.Get already strips the {"data":…} envelope, so decode the inner payload
		// directly (a nested Data wrapper here would double-strip and always yield an
		// empty list — the remote-mode bug this shape previously had).
		var resp struct {
			Projects []*models.Project `json:"projects"`
		}
		if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}
		printProjects(resp.Projects)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}
	printProjects(projects)
	return nil
}

func printProjects(projects []*models.Project) {
	if len(projects) == 0 {
		fmt.Println("No projects found.")
		return
	}
	fmt.Printf("%-5s %-30s %s\n", "ID", "NAME", "DESCRIPTION")
	fmt.Printf("%-5s %-30s %s\n", "-----", "------------------------------", "-----------")
	for _, p := range projects {
		desc := p.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-5d %-30s %s\n", p.ID, p.Name, desc)
	}
}
