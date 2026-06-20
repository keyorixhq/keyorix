// secret_name_conformance_deployment.go — the deployment-wide secret-name conformance
// report: every live secret across every project whose name violates the CURRENT naming
// policy, as one list. The naming policy is global, so an admin who adds or tightens it
// wants a single view of all violators across the deployment rather than checking each
// project. The per-project view is [[secret_name_conformance]] (SecretNameConformance);
// this is the admin's all-projects counterpart, parallel to the deployment-wide asset
// inventory ([[secret_inventory_deployment]]) and hygiene rollup. Never reads a value.
// Deployment-wide (route-gated system.read).
package core

import (
	"context"
	"fmt"
)

// DeploymentSecretNameViolation is one naming-policy violation plus its project.
type DeploymentSecretNameViolation struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	SecretNameViolation
}

// DeploymentSecretNameConformanceReport is the deployment-wide conformance summary. The
// policy is global, so PolicyEnabled/Pattern/MaxLength describe the single install-wide
// policy; PolicyEnabled=false means none is configured and the scan is skipped.
type DeploymentSecretNameConformanceReport struct {
	PolicyEnabled bool                            `json:"policy_enabled"`
	Pattern       string                          `json:"pattern,omitempty"`
	MaxLength     int                             `json:"max_length,omitempty"`
	TotalSecrets  int                             `json:"total_secrets"`
	Violations    []DeploymentSecretNameViolation `json:"violations"`
}

// DeploymentSecretNameConformance scans every live secret across all projects (each via
// the per-project SecretNameConformance) and returns those whose name violates the
// current naming policy, each tagged with its project, ordered by project then name.
// Skips the scan entirely when no policy is configured. Never reads a value.
func (c *KeyorixCore) DeploymentSecretNameConformance(ctx context.Context) (*DeploymentSecretNameConformanceReport, error) {
	report := &DeploymentSecretNameConformanceReport{
		PolicyEnabled: c.secretNamePolicy.Enabled,
		Pattern:       c.secretNamePolicy.Pattern,
		MaxLength:     c.secretNamePolicy.MaxLength,
		Violations:    []DeploymentSecretNameViolation{},
	}
	// No policy configured → nothing can be in violation; skip scanning every project.
	if !c.secretNamePolicy.Enabled {
		return report, nil
	}

	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}

	for _, p := range projects {
		sub, err := c.SecretNameConformance(ctx, p.ID)
		if err != nil {
			return nil, fmt.Errorf("project %d conformance: %w", p.ID, err)
		}
		report.TotalSecrets += sub.TotalSecrets
		for _, v := range sub.Violations {
			report.Violations = append(report.Violations, DeploymentSecretNameViolation{
				ProjectID:           p.ID,
				ProjectName:         p.Name,
				SecretNameViolation: v,
			})
		}
	}
	return report, nil
}
