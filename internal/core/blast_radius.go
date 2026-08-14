// blast_radius.go — dependency blast-radius report (ADR-052 extension).
//
// GetBlastRadius builds on the existing impact-analysis foundation
// (GetSecretImpact / transitiveDependents in secret_dependencies.go) and adds
// per-dependent OwnerID, ProjectID, and a RiskLevel classification so operators
// can triage at a glance which teams are affected and how critical the impact is.
//
// RiskLevel is:
//   - "critical" when depth=1 AND the source secret is classified restricted
//     or the dependent is classified restricted.
//   - "high"     when depth=1 OR either endpoint is classified confidential.
//   - "medium"   when depth=2.
//   - "low"      otherwise (depth≥3).
//
// The report is purely metadata — no secret values are read.
package core

import (
	"context"
	"sort"
)

// BlastRadiusNode represents one dependent secret in the impact graph.
type BlastRadiusNode struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	ProjectID  uint   `json:"project_id"`
	OwnerID    uint   `json:"owner_id"`
	Depth      int    `json:"depth"`      // 1 = direct, 2 = transitive, etc.
	RiskLevel  string `json:"risk_level"` // "critical" | "high" | "medium" | "low"
}

// BlastRadiusReport summarises the impact of deleting/rotating a secret.
type BlastRadiusReport struct {
	SourceSecretID   uint              `json:"source_secret_id"`
	SourceSecretName string            `json:"source_secret_name"`
	Dependents       []BlastRadiusNode `json:"dependents"`
	TotalImpact      int               `json:"total_impact"` // == len(Dependents)
	MaxDepth         int               `json:"max_depth"`
	// Truncated is true when either bound was hit: the true dependent count
	// exceeds maxBlastRadiusNodes (#G44), or the BFS hit its depth ceiling
	// (maxDepth in blastBFS) while dependents still existed beyond it (#G24).
	// Either way, Dependents/TotalImpact reflect only the reachable subset,
	// not the true full impact — never silently reported as a complete
	// picture.
	Truncated bool `json:"truncated"`
}

// blastBFSNode is an internal BFS traversal node.
type blastBFSNode struct {
	id    uint
	depth int
}

// maxBlastRadiusNodes bounds the total number of dependent nodes blastBFS will
// return (#G44) — depth alone (maxDepth below) doesn't bound BREADTH: a secret
// with a very wide fan-out at a single depth can still produce an unbounded node
// count, and GetBlastRadius does one storage.GetSecret call PER node afterward
// (an N+1 query pattern), so an unbounded node count is a per-request
// resource-exhaustion vector.
const maxBlastRadiusNodes = 2000

// blastBFS performs a bounded BFS over the dependents adjacency map starting
// from rootID, returning nodes ordered by (depth, id). Max depth is 10; max
// total nodes is maxBlastRadiusNodes. truncated is true when any node reached
// maxDepth — the BFS stops expanding a node once it hits the ceiling, so a
// node's own further dependents (if any) are never discovered; reaching the
// ceiling at all means the true tree MAY extend further than what's returned
// (#G24 — conservative: flagged even if that specific node turns out to have
// no further children, since "possibly truncated" must never be silently
// reported as complete). The maxBlastRadiusNodes breadth cap (#G44) is
// reported separately by the caller.
func blastBFS(rootID uint, adj map[uint][]uint) (ordered []blastBFSNode, truncated bool) {
	const maxDepth = 10
	visited := map[uint]bool{rootID: true}
	queue := []blastBFSNode{{id: rootID, depth: 0}}

	for len(queue) > 0 && len(ordered) < maxBlastRadiusNodes {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range adj[cur.id] {
			if visited[dep] {
				continue
			}
			visited[dep] = true
			next := blastBFSNode{id: dep, depth: cur.depth + 1}
			ordered = append(ordered, next)
			if next.depth < maxDepth {
				queue = append(queue, next)
			} else {
				truncated = true
			}
			if len(ordered) >= maxBlastRadiusNodes {
				break
			}
		}
	}
	// Sort by (depth, id) for stable, readable output.
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].depth != ordered[j].depth {
			return ordered[i].depth < ordered[j].depth
		}
		return ordered[i].id < ordered[j].id
	})
	return ordered, truncated
}

// GetBlastRadius returns the full dependency tree downstream of secretID,
// up to a maximum depth of 10 to prevent cycles causing infinite loops.
// Each node carries OwnerID, ProjectID, and a RiskLevel assessment.
//
// #G32: the BFS traverses the full graph (a hop through a peer the caller isn't
// independently authorized on still surfaces further, independently-authorized
// dependents), but a node the caller has no grant of their own on is never disclosed
// in the returned report — same-environment membership alone is not sufficient, since
// a per-secret ACL grant on secretID does not extend to a peer.
func (k *KeyorixCore) GetBlastRadius(ctx context.Context, actorKind string, actorID, secretID uint) (*BlastRadiusReport, error) {
	source, err := k.requireSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	edges, err := k.storage.ListSecretDependenciesForProject(ctx, source.ProjectID)
	if err != nil {
		return nil, err
	}

	// Apply the same environment-scoped defence-in-depth used by GetSecretImpact
	// so the blast radius is confined to the focal secret's environment.
	info := k.resolveSecretInfo(ctx, edges)
	edges = edgesWithinEnvironment(edges, info, source.EnvironmentID)

	adj := dependentsAdjacency(edges)
	ordered, truncated := blastBFS(secretID, adj)

	maxDepthSeen := 0
	nodes := make([]BlastRadiusNode, 0, len(ordered))
	for _, o := range ordered {
		if !k.canReadSecret(ctx, actorKind, actorID, o.id) {
			continue // #G32: don't disclose a peer the caller isn't independently authorized to see
		}
		dep, depErr := k.storage.GetSecret(ctx, o.id)
		if depErr != nil {
			// Dependent no longer exists (soft-deleted); skip it gracefully.
			continue
		}
		risk := blastRiskLevel(o.depth, source.Classification, dep.Classification)
		node := BlastRadiusNode{
			SecretID:   dep.ID,
			SecretName: dep.Name,
			ProjectID:  dep.ProjectID,
			OwnerID:    dep.OwnerID,
			Depth:      o.depth,
			RiskLevel:  risk,
		}
		nodes = append(nodes, node)
		if o.depth > maxDepthSeen {
			maxDepthSeen = o.depth
		}
	}

	return &BlastRadiusReport{
		SourceSecretID:   source.ID,
		SourceSecretName: source.Name,
		Dependents:       nodes,
		TotalImpact:      len(nodes),
		MaxDepth:         maxDepthSeen,
		Truncated:        truncated || len(ordered) >= maxBlastRadiusNodes,
	}, nil
}

// blastRiskLevel assigns a risk tier to a dependent based on its hop-distance
// and the classification labels of the source and the dependent.
//
// Tier logic (highest matching rule wins):
//   - "critical": depth==1 AND (source OR dependent is "restricted")
//   - "high":     depth==1 OR (source OR dependent is "confidential" OR "restricted")
//   - "medium":   depth==2
//   - "low":      depth>=3
func blastRiskLevel(depth int, sourceClass, depClass string) string {
	isRestricted := func(c string) bool { return c == "restricted" }
	isHighSensitivity := func(c string) bool { return c == "confidential" || c == "restricted" }

	switch {
	case depth == 1 && (isRestricted(sourceClass) || isRestricted(depClass)):
		return "critical"
	case depth == 1 || isHighSensitivity(sourceClass) || isHighSensitivity(depClass):
		return "high"
	case depth == 2:
		return "medium"
	default:
		return "low"
	}
}
