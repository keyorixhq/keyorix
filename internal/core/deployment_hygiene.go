// deployment_hygiene.go — install-wide hygiene rollup: aggregate every project's
// hygiene posture (orphaned / unused / expiring secrets, stale machine identities,
// rotation-overdue) into deployment-wide totals plus a per-project breakdown of the
// projects that actually carry debt. Counts only — no secret names or values — but
// the per-project breakdown DOES name every project deployment-wide, which a
// zero-membership account has no other route to see, so the route requires audit.read
// (not the universal system_viewer baseline system.read; see #273). Parallels the
// deployment-wide PAT ([[pat_hygiene]]) and machine-token hygiene views; built on the
// per-project [[project_hygiene]] summary. Each signal is computed via a single
// deployment-wide (grouped) query rather than one call per project — see the #393
// fix note on DeploymentHygieneSummary.
package core

import (
	"context"
	"fmt"
	"sort"
	"time"
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
//
// #393: this used to call ProjectHygieneSummary once PER PROJECT — five separate DB
// round trips (orphaned/unused/expiring/stale-MI/rotation-overdue), repeated for
// every project in the deployment, with no pagination or cap anywhere in the chain.
// A deployment with many projects made a single call to this route (reachable well
// below system_admin) take arbitrarily long and issue an arbitrarily large number of
// queries — a DoS-adjacent cost with no relationship to what the caller asked for.
// Each signal is now computed ONCE, deployment-wide, either via a dedicated grouped
// (`GROUP BY project_id`) storage query, or — for rotation-overdue, which was
// already exposed as a single deployment-wide call (see compliance_posture.go) — by
// grouping its one deployment-wide result in memory. Total DB round trips is now a
// small constant regardless of project count: this endpoint's whole purpose is a
// cross-project aggregate, so a set-based query is both the natural and the cheap
// shape for it, matching the #238 fix's targeted-query pattern for the same family
// of bug.
func (c *KeyorixCore) DeploymentHygieneSummary(ctx context.Context, unusedDays, expiringDays, staleMIDays int) (*DeploymentHygiene, error) {
	if unusedDays <= 0 {
		unusedDays = defaultHygieneUnusedDays
	}
	if expiringDays <= 0 {
		expiringDays = defaultHygieneExpiringDays
	}
	if staleMIDays <= 0 {
		staleMIDays = defaultHygieneStaleMIDays
	}

	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	projectIDs := make([]uint, len(projects))
	names := make(map[uint]string, len(projects))
	for i, p := range projects {
		projectIDs[i] = p.ID
		names[p.ID] = p.Name
	}

	orphaned, err := c.storage.CountOrphanedSecretsByProject(ctx, projectIDs)
	if err != nil {
		return nil, fmt.Errorf("orphaned secrets: %w", err)
	}
	unused, err := c.storage.CountUnusedSecretsByProject(ctx, projectIDs, c.now().Add(-time.Duration(unusedDays)*24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("unused secrets: %w", err)
	}
	expiringCutoff := c.now().Add(time.Duration(expiringDays) * 24 * time.Hour)
	expiring, err := c.storage.CountExpiringSecretsByProject(ctx, projectIDs, expiringCutoff)
	if err != nil {
		return nil, fmt.Errorf("expiring secrets: %w", err)
	}
	staleMI, err := c.storage.CountStaleMachineIdentitiesByProject(ctx, projectIDs, c.now().Add(-time.Duration(staleMIDays)*24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("stale machine identities: %w", err)
	}

	// GetRotationStatus(nil, nil) is already the established deployment-wide call
	// (compliance_posture.go uses it the same way) — a single ListRotationPolicies
	// query plus a per-POLICY (not per-project) scan of that policy's covered
	// secrets, so its cost is bounded by the deployment's policy/secret count, not
	// multiplied again by project count the way calling it once per project was.
	statuses, err := c.GetRotationStatus(ctx, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("rotation status: %w", err)
	}
	rotationOverdue := make(map[uint]int)
	for _, s := range statuses {
		if s.Status == RotationStatusOverdue {
			rotationOverdue[s.ProjectID]++
		}
	}

	// Union of every project ID carrying at least one outstanding signal.
	flagged := make(map[uint]struct{})
	for _, m := range []map[uint]int{orphaned, unused, expiring, staleMI, rotationOverdue} {
		for pid := range m {
			flagged[pid] = struct{}{}
		}
	}

	out := &DeploymentHygiene{Projects: make([]ProjectHygieneBreakdown, 0, len(flagged))}
	for pid := range flagged {
		ph := ProjectHygiene{
			OrphanedSecrets:        orphaned[pid],
			UnusedSecrets:          unused[pid],
			ExpiringSecrets:        expiring[pid],
			StaleMachineIdentities: staleMI[pid],
			RotationOverdue:        rotationOverdue[pid],
		}
		out.Totals.OrphanedSecrets += ph.OrphanedSecrets
		out.Totals.UnusedSecrets += ph.UnusedSecrets
		out.Totals.ExpiringSecrets += ph.ExpiringSecrets
		out.Totals.StaleMachineIdentities += ph.StaleMachineIdentities
		out.Totals.RotationOverdue += ph.RotationOverdue
		out.Projects = append(out.Projects, ProjectHygieneBreakdown{
			ProjectID:      pid,
			ProjectName:    names[pid],
			ProjectHygiene: ph,
		})
	}
	// Grouped-query results and a map iteration order are both otherwise
	// nondeterministic; sort by ID so the response is stable across calls.
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].ProjectID < out.Projects[j].ProjectID })

	return out, nil
}
