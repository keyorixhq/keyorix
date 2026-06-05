// machine.go — CLI commands for managing machine identities (ADR-023).
//
// Commands: machine list, machine create, machine describe, machine suspend,
//
//	machine reactivate, machine revoke.
//
// Each command works in both remote mode (against the server API) and local
// mode (directly against the core service), mirroring the project CLI. Machine
// identities are project-scoped, so every command resolves a project from
// --project / KEYORIX_PROJECT / the active project. Machine-token issuance and
// authentication are a separate follow-up (they need the machine-principal
// model); this CLI manages the identity lifecycle.
package machine

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// MachineCmd is the root command for machine identity management.
var MachineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage machine identities",
	Long:  "Commands for listing, creating, and managing the lifecycle of project machine identities (CI, k8s, services, automation).",
}

func init() {
	MachineCmd.AddCommand(listCmd)
	MachineCmd.AddCommand(createCmd)
	MachineCmd.AddCommand(describeCmd)
	MachineCmd.AddCommand(suspendCmd)
	MachineCmd.AddCommand(reactivateCmd)
	MachineCmd.AddCommand(revokeCmd)
}

// resolveProjectContext resolves a project name (flag / env / active) to its
// numeric ID, in both remote and local modes.
func resolveProjectContext(flagValue string) (string, uint, error) {
	name, err := common.ResolveProject(flagValue)
	if err != nil {
		return "", 0, err
	}
	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		var resp struct {
			Data struct {
				Projects []struct {
					ID   uint   `json:"id"`
					Name string `json:"name"`
				} `json:"projects"`
			} `json:"data"`
		}
		if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
			return "", 0, fmt.Errorf("failed to list projects: %w", err)
		}
		for _, p := range resp.Data.Projects {
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

// fetchMachineIdentities lists a project's machine identities (remote or local).
func fetchMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	if rc, ok := common.NewRemoteClient(); ok {
		var resp struct {
			Data struct {
				MachineIdentities []*models.MachineIdentity `json:"machine_identities"`
			} `json:"data"`
		}
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID)
		if err := rc.Get(ctx, path, &resp); err != nil {
			return nil, err
		}
		return resp.Data.MachineIdentities, nil
	}
	svc, err := common.InitializeCoreService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service: %w", err)
	}
	return svc.ListMachineIdentities(ctx, projectID)
}

// findMachineByRef finds a machine identity in a project by numeric ID or name.
func findMachineByRef(ctx context.Context, projectID uint, ref string) (*models.MachineIdentity, error) {
	identities, err := fetchMachineIdentities(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list machine identities: %w", err)
	}
	for _, m := range identities {
		if m.Name == ref || fmt.Sprintf("%d", m.ID) == ref {
			return m, nil
		}
	}
	return nil, fmt.Errorf("machine identity %q not found in project", ref)
}
