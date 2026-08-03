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
}

// blastBFSNode is an internal BFS traversal node.
type blastBFSNode struct {
	id    uint
	depth int
}

// blastBFS performs a bounded BFS over the dependents adjacency map starting
// from rootID, returning nodes ordered by (depth, id). Max depth is 10.
func blastBFS(rootID uint, adj map[uint][]uint) []blastBFSNode {
	const maxDepth = 10
	visited := map[uint]bool{rootID: true}
	queue := []blastBFSNode{{id: rootID, depth: 0}}
	var ordered []blastBFSNode

	for len(queue) > 0 {
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
	return ordered
}

// GetBlastRadius returns the full dependency tree downstream of secretID,
// up to a maximum depth of 10 to prevent cycles causing infinite loops.
// Each node carries OwnerID, ProjectID, and a RiskLevel assessment.
func (k *KeyorixCore) GetBlastRadius(ctx context.Context, secretID uint) (*BlastRadiusReport, error) {
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
	ordered := blastBFS(secretID, adj)

	maxDepthSeen := 0
	nodes := make([]BlastRadiusNode, 0, len(ordered))
	for _, o := range ordered {
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
