// secret_inventory_deployment.go — the deployment-wide secret asset inventory: every
// live secret across every project as one metadata manifest (no values), for an
// org-wide ISO 27001 A.5.9 asset register. The per-project view is [[secret_inventory]]
// (SecretsInventory); this is the admin's all-projects counterpart, parallel to the
// deployment-wide hygiene rollup. Counts/metadata only. Deployment-wide (route-gated
// system.read).
package core

import (
	"context"
	"fmt"
)

// DeploymentSecretInventoryItem is one secret's metadata row plus its project, for the
// org-wide manifest. Never a value.
type DeploymentSecretInventoryItem struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	SecretInventoryItem
}

// DeploymentSecretsInventory returns the metadata manifest of every live secret across
// all projects, project-by-project (each project's secrets resolved via the per-project
// inventory), ordered by project then environment then name. Never reads a value.
func (c *KeyorixCore) DeploymentSecretsInventory(ctx context.Context) ([]DeploymentSecretInventoryItem, error) {
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}

	out := make([]DeploymentSecretInventoryItem, 0)
	for _, p := range projects {
		items, err := c.SecretsInventory(ctx, p.ID)
		if err != nil {
			return nil, fmt.Errorf("project %d inventory: %w", p.ID, err)
		}
		for _, it := range items {
			out = append(out, DeploymentSecretInventoryItem{
				ProjectID:           p.ID,
				ProjectName:         p.Name,
				SecretInventoryItem: it,
			})
		}
	}
	return out, nil
}
