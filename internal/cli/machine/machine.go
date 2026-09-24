// machine.go — CLI commands for managing machine identities (ADR-023).
//
// Commands: machine list, machine create, machine describe, machine suspend,
//
//	machine reactivate, machine revoke.
//
// Each command works in both remote mode (against the server API) and local
// mode (directly against the core service), mirroring the project CLI. Machine
// identities are project-scoped, so every command resolves a project from
// --project / KEYORIX_PROJECT / the active project. Machine-token issuance,
// authentication, and revocation (ADR-030) are fully implemented and reachable
// via the HTTP/gRPC APIs (see internal/core/machine_token.go); this package
// manages the identity lifecycle plus token-hygiene reporting
// (token_hygiene.go) — it does not yet expose its own issue/revoke subcommand.
package machine

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// machineIdentityWire mirrors server/http/handlers/machine_identities_proxy.go's
// machineIdentityProxyWire: models.MachineIdentity carries no json tags of its own,
// so decoding the server's snake_case JSON directly into it would silently leave
// every underscored field (identity_type, project_id, created_by, ...) zero-valued
// -- Go's fallback field-name matching for an untagged struct is case-insensitive
// only, it does not bridge "identity_type" to IdentityType. Found live
// (docs/cli-split-inventory.md PR 2's verification step: `machine list`/`machine
// create` silently rendered an empty type/project column) after the server's
// CreateMachineIdentity/ListMachineIdentities handlers were fixed to actually send
// this API's documented snake_case shape instead of Go-cased field names.
type machineIdentityWire struct {
	ID                         uint       `json:"id"`
	ProjectID                  uint       `json:"project_id"`
	Name                       string     `json:"name"`
	IdentityType               string     `json:"identity_type"`
	State                      string     `json:"state"`
	Description                string     `json:"description"`
	CreatedBy                  uint       `json:"created_by"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
	LastSeenAt                 *time.Time `json:"last_seen_at"`
	RevokedAt                  *time.Time `json:"revoked_at"`
	Classification             string     `json:"classification"`
	CreatedByMachineIdentityID uint       `json:"created_by_machine_identity_id"`
}

func (w machineIdentityWire) toModel() *models.MachineIdentity {
	return &models.MachineIdentity{
		ID:                         w.ID,
		ProjectID:                  w.ProjectID,
		Name:                       w.Name,
		IdentityType:               w.IdentityType,
		State:                      w.State,
		Description:                w.Description,
		CreatedBy:                  w.CreatedBy,
		CreatedAt:                  w.CreatedAt,
		UpdatedAt:                  w.UpdatedAt,
		LastSeenAt:                 w.LastSeenAt,
		RevokedAt:                  w.RevokedAt,
		Classification:             w.Classification,
		CreatedByMachineIdentityID: w.CreatedByMachineIdentityID,
	}
}

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

// fetchMachineIdentities lists a project's machine identities (remote or local).
func fetchMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	if rc, ok := common.NewRemoteClient(); ok {
		// rc.Get already strips the {"data":…} envelope — decode the inner payload directly.
		var resp struct {
			MachineIdentities []machineIdentityWire `json:"machine_identities"`
		}
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID)
		if err := rc.Get(ctx, path, &resp); err != nil {
			return nil, err
		}
		out := make([]*models.MachineIdentity, len(resp.MachineIdentities))
		for i, w := range resp.MachineIdentities {
			out[i] = w.toModel()
		}
		return out, nil
	}
	svc, err := common.InitializeCoreService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service: %w", err)
	}
	return svc.ListMachineIdentities(ctx, projectID)
}

// findMachineByRef finds a machine identity in a project by numeric ID or name.
//
// A ref that parses as a valid numeric ID is ALWAYS resolved as an ID lookup —
// it never falls through to a Name match, even if no identity has that ID. The
// server enforces no uniqueness between the Name and ID spaces (a purely
// numeric Name like "5" is accepted), so an attacker-planted decoy identity
// named after a real target's numeric ID could otherwise shadow the intended
// machine and get resolved instead — silently redirecting destructive
// operations (revoke/suspend) and defeating their typed-name confirmation
// step, since the confirmation prompt echoes back the (decoy) match's own
// Name, which trivially equals what the operator already typed (G78).
func findMachineByRef(ctx context.Context, projectID uint, ref string) (*models.MachineIdentity, error) {
	identities, err := fetchMachineIdentities(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list machine identities: %w", err)
	}
	if id, err := strconv.ParseUint(ref, 10, 64); err == nil {
		for _, m := range identities {
			if uint64(m.ID) == id {
				return m, nil
			}
		}
		return nil, fmt.Errorf("machine identity %q not found in project", ref)
	}
	for _, m := range identities {
		if m.Name == ref {
			return m, nil
		}
	}
	return nil, fmt.Errorf("machine identity %q not found in project", ref)
}
