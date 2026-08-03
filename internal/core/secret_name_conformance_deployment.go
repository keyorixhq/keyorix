// secret_name_conformance_deployment.go — the deployment-wide secret-name conformance
// report: every live secret across every project whose name violates the CURRENT naming
// policy, as one list. The naming policy is global, so an admin who adds or tightens it
// wants a single view of all violators across the deployment rather than checking each
// project. The per-project view is [[secret_name_conformance]] (SecretNameConformance);
// this is the admin's all-projects counterpart, parallel to the deployment-wide asset
// inventory ([[secret_inventory_deployment]]) and hygiene rollup. Never reads a value.
// Deployment-wide (route-gated audit.read — it discloses real secret names, so the
// universal system_viewer baseline is not enough).
package core

import (
	"context"
	"fmt"
	"sort"
)

// deploymentSecretNameConformanceMaxRows bounds the single deployment-wide query the
// conformance scan issues (#416) — analogous to secretInventoryMaxRows/
// secretListingMaxRows, but a larger ceiling since this one query covers every
// project in the deployment rather than a single project at a time. Truncated on
// the report signals the (rare) case a deployment actually has more live secrets
// than this, instead of silently dropping the rest.
const deploymentSecretNameConformanceMaxRows = 100000

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
	PolicyEnabled bool   `json:"policy_enabled"`
	Pattern       string `json:"pattern,omitempty"`
	MaxLength     int    `json:"max_length,omitempty"`
	TotalSecrets  int    `json:"total_secrets"`
	// Truncated reports whether deploymentSecretNameConformanceMaxRows was hit, i.e.
	// the deployment has more live secrets than this scan pulled in a single query —
	// the result above is then a (possibly incomplete) sample, not the full set.
	Truncated  bool                            `json:"truncated,omitempty"`
	Violations []DeploymentSecretNameViolation `json:"violations"`
}

// DeploymentSecretNameConformance returns every live secret across all projects whose
// name violates the current naming policy, each tagged with its project, ordered by
// project then name. Skips the scan entirely when no policy is configured. Never
// reads a value.
//
// #416: this used to call SecretNameConformance once PER PROJECT — a full
// ListSecrets query per project, repeated for every project in the deployment, with
// no bound on project count — the same N+1/unbounded fan-out family as #238/#393. A
// deployment with many projects made a single call to this route take arbitrarily
// long and issue an arbitrarily large number of queries. Naming-policy conformance
// can't be pushed into SQL as a pure aggregate (matching a caller-configured regex
// isn't a database concern), so the fix here is narrower than #393's grouped-COUNT
// approach: fetch every project's live secret names in ONE bounded query
// (ListLiveSecretNamesByProject) and run the regex check in memory, exactly as
// SecretNameConformance already does per-project — only the N+1 QUERY pattern is
// eliminated, not the in-memory regex work (which was never the bottleneck). Total
// DB round trips is now a small constant regardless of project count.
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
	if len(projects) == 0 {
		return report, nil
	}

	projectIDs := make([]uint, len(projects))
	projectName := make(map[uint]string, len(projects))
	for i, p := range projects {
		projectIDs[i] = p.ID
		projectName[p.ID] = p.Name
	}

	rows, truncated, err := c.storage.ListLiveSecretNamesByProject(ctx, projectIDs, deploymentSecretNameConformanceMaxRows)
	if err != nil {
		return nil, fmt.Errorf("list secret names: %w", err)
	}
	report.Truncated = truncated
	report.TotalSecrets = len(rows)

	for _, r := range rows {
		if verr := c.validateSecretName(r.Name); verr != nil {
			report.Violations = append(report.Violations, DeploymentSecretNameViolation{
				ProjectID:   r.ProjectID,
				ProjectName: projectName[r.ProjectID],
				SecretNameViolation: SecretNameViolation{
					ID:             r.ID,
					Name:           r.Name,
					Type:           r.Type,
					Classification: r.Classification,
					EnvironmentID:  r.EnvironmentID,
					Reason:         verr.Error(),
				},
			})
		}
	}

	sort.Slice(report.Violations, func(i, j int) bool {
		if report.Violations[i].ProjectID != report.Violations[j].ProjectID {
			return report.Violations[i].ProjectID < report.Violations[j].ProjectID
		}
		return report.Violations[i].Name < report.Violations[j].Name
	})
	return report, nil
}
