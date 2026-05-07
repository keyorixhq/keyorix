// describe.go — keyorix project describe [name]
// Shows project details: environments, member count, secret count (ADR-016).
package project

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var describeCmd = &cobra.Command{
	Use:   "describe [name]",
	Short: "Show details of a project",
	Long:  "Displays environments, member count, and secret count for the specified project (or the active project if none given).",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDescribe,
}

func runDescribe(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	var name string
	if len(args) == 1 {
		name = args[0]
	} else {
		var err error
		name, err = common.ResolveProject("")
		if err != nil {
			return err
		}
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return describeViaRemote(ctx, rc, name)
	}
	return describeViaLocal(ctx, name)
}

func describeViaRemote(ctx context.Context, rc *common.RemoteClient, name string) error {
	// List projects to find the ID.
	var listResp struct {
		Data struct {
			Projects []struct {
				ID          uint   `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"projects"`
		} `json:"data"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &listResp); err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}
	var projectID uint
	var description string
	for _, p := range listResp.Data.Projects {
		if p.Name == name {
			projectID = p.ID
			description = p.Description
			break
		}
	}
	if projectID == 0 {
		return fmt.Errorf("project %q not found", name)
	}

	// Environments.
	var envResp struct {
		Data struct {
			Environments []*models.Environment `json:"environments"`
		} `json:"data"`
	}
	envPath := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/environments"
	if err := rc.Get(ctx, envPath, &envResp); err != nil {
		return fmt.Errorf("failed to list environments: %w", err)
	}

	printProjectDetails(name, description, projectID, envResp.Data.Environments)
	return nil
}

func describeViaLocal(ctx context.Context, name string) error {
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}
	var projectID uint
	var description string
	for _, p := range projects {
		if p.Name == name {
			projectID = p.ID
			description = p.Description
			break
		}
	}
	if projectID == 0 {
		return fmt.Errorf("project %q not found", name)
	}

	envs, err := svc.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to list environments: %w", err)
	}

	// Count secrets.
	_, secretTotal, err := svc.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		Page:      1,
		PageSize:  1,
	})
	if err != nil {
		secretTotal = -1
	}

	printProjectDetails(name, description, projectID, envs)
	if secretTotal >= 0 {
		fmt.Printf("Secrets:      %d\n", secretTotal)
	}
	return nil
}

func printProjectDetails(name, description string, id uint, envs []*models.Environment) {
	fmt.Printf("Project:      %s (id=%d)\n", name, id)
	if description != "" {
		fmt.Printf("Description:  %s\n", description)
	}
	fmt.Printf("Environments: %d\n", len(envs))
	for _, e := range envs {
		fmt.Printf("  - %s (id=%d)\n", e.Name, e.ID)
	}
}
