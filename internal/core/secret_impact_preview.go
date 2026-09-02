// secret_impact_preview.go — cascade-delete impact preview for a secret (ADR-052
// companion). Answers "if I soft-delete this secret, how many secrets would also
// be cascade-deleted?" — a flat count/summary rather than the full dependency
// graph that GetSecretImpact returns. Re-uses the same storage calls and BFS
// helpers as the existing dependency analysis.
package core

import "context"

// ImpactPreviewResult is the response payload for
// GET /api/v1/secrets/{id}/impact-preview.
type ImpactPreviewResult struct {
	SecretID             uint   `json:"secret_id"`
	DirectDependents     int    `json:"direct_dependents"`     // secrets that directly depend on this one (depth=1)
	TransitiveDependents int    `json:"transitive_dependents"` // transitive-closure count (excludes root), up to maxDependencyBFSNodes
	AffectedSecretIDs    []uint `json:"affected_secret_ids"`   // IDs of all transitively affected secrets found
	MaxDepth             int    `json:"max_depth"`             // deepest dependency chain length found
	// Truncated is true when the true cascade extends beyond what the counts
	// above report -- the underlying BFS hit maxDependencyBFSNodes or
	// maxDependencyBFSDepth (see transitiveDependents). When true, every
	// count above is a LOWER BOUND, not the true cascade size.
	Truncated bool `json:"truncated"`
}

// GetSecretImpactPreview computes the cascade-delete impact of removing secretID.
//
// It reuses the same SecretDependency storage infrastructure as GetSecretImpact /
// ListSecretDependencies: one ListSecretDependenciesForProject call loads the
// project's full edge list, edgesWithinEnvironment restricts it to the secret's
// own environment (defence-in-depth), and transitiveDependents does a BFS to find
// every dependent in the "dependents" direction (i.e. secrets that depend on
// secretID and would therefore lose their upstream if secretID were deleted).
//
// The result is a flat count/summary, not the annotated node graph that
// GetSecretImpact returns.
//
// #G32: DirectDependents/TransitiveDependents/MaxDepth are computed over the FULL
// graph (not filtered to what the caller can see) — an operator deciding whether to
// delete secretID needs the true cascade size, even if some affected secrets are
// outside their own visibility, and a bare count discloses no peer identity.
// AffectedSecretIDs is the identifying part, though, so it is filtered to only the
// peers the caller is independently authorized to read (same reasoning as
// ListSecretDependencies/GetSecretImpact: same-environment membership alone does not
// prove authorization on a peer). "Full graph" is itself bounded by
// transitiveDependents' maxDependencyBFSNodes/maxDependencyBFSDepth (resource-
// exhaustion guard, same as GetBlastRadius's maxBlastRadiusNodes) — Truncated
// signals when a pathologically large dependency graph made these counts a lower
// bound rather than the true cascade size.
func (c *KeyorixCore) GetSecretImpactPreview(ctx context.Context, actorKind string, actorID, secretID uint) (*ImpactPreviewResult, error) {
	secret, err := c.requireSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	edges, err := c.storage.ListSecretDependenciesForProject(ctx, secret.ProjectID)
	if err != nil {
		return nil, err
	}

	info := c.resolveSecretInfo(ctx, edges)
	// Defence-in-depth: restrict to the focal secret's environment only, matching
	// the same guard in ListSecretDependencies and GetSecretImpact.
	edges = edgesWithinEnvironment(edges, info, secret.EnvironmentID)

	// transitiveDependents walks the "dependents" direction (secrets that depend ON
	// secretID), which is the correct direction for cascade-delete impact: if secretID
	// is removed, every secret that depended on it is affected.
	affected, truncated := transitiveDependents(edges, secretID)

	result := &ImpactPreviewResult{
		SecretID:          secretID,
		AffectedSecretIDs: make([]uint, 0, len(affected)),
		Truncated:         truncated,
	}

	for _, a := range affected {
		result.TransitiveDependents++
		if a.depth == 1 {
			result.DirectDependents++
		}
		if a.depth > result.MaxDepth {
			result.MaxDepth = a.depth
		}
		if c.canReadSecret(ctx, actorKind, actorID, a.id) {
			result.AffectedSecretIDs = append(result.AffectedSecretIDs, a.id)
		}
	}

	return result, nil
}
