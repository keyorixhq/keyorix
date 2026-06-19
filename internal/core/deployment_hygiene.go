// deployment_hygiene.go — install-wide hygiene rollup: aggregate every project's
// hygiene posture (orphaned / unused / expiring secrets, stale machine identities,
// rotation-overdue) into deployment-wide totals plus a per-project breakdown of the
// projects that actually carry debt. Counts only — no names or values of secrets —
// so it is safe to surface to an admin overseeing many projects, and cheap enough to
// poll for a dashboard. Parallels the deployment-wide PAT ([[pat_hygiene]]) and
// machine-token hygiene views; built on the per-project [[project_hygiene]] summary.
package core

import (
	"context"
	"fmt"
)

// DeploymentHygiene is the install-wide hygiene rollup: summed totals across all
// projects plus a per-project breakdown limited to projects with outstanding signals.
type DeploymentHygiene struct {
	Totals   ProjectHygiene            `json:"totals"`
	Projects []ProjectHygieneBreakdown `json:"projects"`
}

// ProjectHygieneBreakdown is one project's hygiene counts, identified for the admin.
type ProjectHygieneBreakdown struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	ProjectHygiene
}

// DeploymentHygieneSummary sums each hygiene signal across every (live) project and
// lists the projects with at least one outstanding signal. Healthy projects are
// omitted from the breakdown but contribute their (zero) counts to the totals. The
// windows (in days) default when non-positive, matching ProjectHygieneSummary.
func (c *KeyorixCore) DeploymentHygieneSummary(ctx context.Context, unusedDays, expiringDays, staleMIDays int) (*DeploymentHygiene, error) {
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}

	out := &DeploymentHygiene{Projects: make([]ProjectHygieneBreakdown, 0)}
	for _, p := range projects {
		summary, err := c.ProjectHygieneSummary(ctx, p.ID, unusedDays, expiringDays, staleMIDays)
		if err != nil {
			return nil, fmt.Errorf("project %d hygiene: %w", p.ID, err)
		}
		out.Totals.OrphanedSecrets += summary.OrphanedSecrets
		out.Totals.UnusedSecrets += summary.UnusedSecrets
		out.Totals.ExpiringSecrets += summary.ExpiringSecrets
		out.Totals.StaleMachineIdentities += summary.StaleMachineIdentities
		out.Totals.RotationOverdue += summary.RotationOverdue

		if summary.OrphanedSecrets+summary.UnusedSecrets+summary.ExpiringSecrets+
			summary.StaleMachineIdentities+summary.RotationOverdue > 0 {
			out.Projects = append(out.Projects, ProjectHygieneBreakdown{
				ProjectID:      p.ID,
				ProjectName:    p.Name,
				ProjectHygiene: *summary,
			})
		}
	}
	return out, nil
}
