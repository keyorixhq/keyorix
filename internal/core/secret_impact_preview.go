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
	DirectDependents     int    `json:"direct_dependents"`   // secrets that directly depend on this one (depth=1)
	TransitiveDependents int    `json:"transitive_dependents"` // full transitive-closure count (excludes root)
	AffectedSecretIDs    []uint `json:"affected_secret_ids"` // IDs of all transitively affected secrets
	MaxDepth             int    `json:"max_depth"`           // deepest dependency chain length found
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
func (c *KeyorixCore) GetSecretImpactPreview(ctx context.Context, secretID uint) (*ImpactPreviewResult, error) {
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
	affected := transitiveDependents(edges, secretID)

	result := &ImpactPreviewResult{
		SecretID:          secretID,
		AffectedSecretIDs: make([]uint, 0, len(affected)),
	}

	for _, a := range affected {
		result.AffectedSecretIDs = append(result.AffectedSecretIDs, a.id)
		result.TransitiveDependents++
		if a.depth == 1 {
			result.DirectDependents++
		}
		if a.depth > result.MaxDepth {
			result.MaxDepth = a.depth
		}
	}

	return result, nil
}
