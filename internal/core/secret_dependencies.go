// secret_dependencies.go — the per-project secret dependency graph (ADR-052).
// An operator declares that one secret "depends on" another (e.g. an app token
// derived from a DB password); Keyorix maintains the directed graph and answers two
// questions from it: impact analysis ("if I rotate this secret, what else is
// affected?" — its transitive dependents) and rotation ordering (a safe sequence to
// rotate a project's secrets so each is rotated before anything that depends on it).
// The graph is kept acyclic: self-edges, duplicates, and cycles are rejected at add.
// Metadata only — secret values are never read. Authz is enforced at the HTTP layer
// (secrets.read to view, secrets.write to mutate), scoped to the secret's project.
package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Secret-dependency audit event types.
const (
	EventSecretDependencyAdded   = "secret.dependency_added"   // #nosec G101 -- audit event type, not a credential
	EventSecretDependencyRemoved = "secret.dependency_removed" // #nosec G101 -- audit event type, not a credential
)

// SecretRef is a secret identified for a dependency view (id + name; never a value).
type SecretRef struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
}

// DependencyEdge is one edge as seen from a focal secret: the other secret it links
// to, plus the edge id (so it can be removed) and the operator's note.
type DependencyEdge struct {
	ID         uint   `json:"id"`
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Note       string `json:"note,omitempty"`
}

// SecretDependencies is a focal secret's direct neighbours in both directions.
type SecretDependencies struct {
	SecretID   uint             `json:"secret_id"`
	DependsOn  []DependencyEdge `json:"depends_on"` // secrets this one depends on
	Dependents []DependencyEdge `json:"dependents"` // secrets that depend on this one
}

// ImpactedSecret is a transitive dependent reached during impact analysis, with the
// shortest hop-distance from the rotated secret.
type ImpactedSecret struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Depth      int    `json:"depth"`
}

// SecretImpact is the blast radius of rotating/changing a secret.
type SecretImpact struct {
	SecretID   uint             `json:"secret_id"`
	SecretName string           `json:"secret_name"`
	Affected   []ImpactedSecret `json:"affected"`
}

// RotationOrder is a safe rotation sequence for a project's dependency graph: each
// secret appears before any secret that depends on it.
type RotationOrder struct {
	ProjectID uint        `json:"project_id"`
	Order     []SecretRef `json:"order"`
}

// AddSecretDependency declares that dependentID depends on dependsOnID. Both must be
// real secrets in the same project; self-edges, duplicates, and edges that would
// introduce a cycle are rejected. actorID is the acting principal.
func (c *KeyorixCore) AddSecretDependency(ctx context.Context, actorID, dependentID, dependsOnID uint, note string) (*models.SecretDependency, error) {
	if dependentID == dependsOnID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a secret cannot depend on itself")
	}
	dependent, err := c.requireSecret(ctx, dependentID)
	if err != nil {
		return nil, err // the caller is authorized on the path secret, so its status may differ
	}
	// Resolve the dependency target, but DON'T distinguish "not found" / "is a folder" /
	// "in another project or environment" — the caller is only authorized on the path
	// (dependent) secret's scope, so a differentiated error here is a cross-scope
	// existence-and-type oracle (probe arbitrary IDs by 404-vs-400). Collapse them into a
	// single opaque error. Confining the edge to the same project AND environment is also
	// what makes the path-secret authorization cover the dependency secret (authorization
	// is environment-granular and the HTTP layer authorizes only the path secret's env).
	dependsOn, derr := c.requireSecret(ctx, dependsOnID)
	if derr != nil || dependsOn.ProjectID != dependent.ProjectID || dependsOn.EnvironmentID != dependent.EnvironmentID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the dependency target must be a secret in the same project and environment")
	}

	edges, err := c.storage.ListSecretDependenciesForProject(ctx, dependent.ProjectID)
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		if e.DependentSecretID == dependentID && e.DependsOnSecretID == dependsOnID {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this dependency already exists")
		}
	}
	// A cycle would form iff dependsOnID can already reach dependentID over existing
	// edges (then dependent → dependsOn → … → dependent closes the loop).
	if dependencyReachable(edges, dependsOnID, dependentID) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this dependency would create a cycle")
	}

	created, err := c.storage.CreateSecretDependency(ctx, &models.SecretDependency{
		ProjectID:         dependent.ProjectID,
		DependentSecretID: dependentID,
		DependsOnSecretID: dependsOnID,
		Note:              note,
		CreatedBy:         actorID,
		CreatedAt:         c.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventSecretDependencyAdded, actorPtr(actorID), &dependentID,
		fmt.Sprintf("declared secret %q depends on %q", dependent.Name, dependsOn.Name))
	return created, nil
}

// RemoveSecretDependency deletes one edge. focalSecretID is the secret the request is
// scoped to (the {id} in the route): the edge must actually reference that secret, so
// the environment-scoped authorization the caller passed on focalSecretID also governs
// the edge. Matching on project alone would be too coarse — authorization is
// environment-granular, and a caller could otherwise delete an edge between two secrets
// in another environment of the same project. actorID is the acting principal.
func (c *KeyorixCore) RemoveSecretDependency(ctx context.Context, actorID, focalSecretID, edgeID uint) error {
	if _, err := c.requireSecret(ctx, focalSecretID); err != nil {
		return err
	}
	edge, err := c.storage.GetSecretDependency(ctx, edgeID)
	if err != nil {
		return err
	}
	if edge.DependentSecretID != focalSecretID && edge.DependsOnSecretID != focalSecretID {
		return fmt.Errorf("%s: dependency %d does not reference secret %d", i18n.T("ErrorNotFound", nil), edgeID, focalSecretID)
	}
	if err := c.storage.DeleteSecretDependency(ctx, edgeID); err != nil {
		return err
	}
	dep := edge.DependentSecretID
	c.writeAuditEvent(ctx, EventSecretDependencyRemoved, actorPtr(actorID), &dep,
		fmt.Sprintf("removed dependency of secret %d on secret %d", edge.DependentSecretID, edge.DependsOnSecretID))
	return nil
}

// ListSecretDependencies returns a secret's direct dependencies and dependents, with
// names resolved.
func (c *KeyorixCore) ListSecretDependencies(ctx context.Context, secretID uint) (*SecretDependencies, error) {
	secret, err := c.requireSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	edges, err := c.storage.ListSecretDependenciesForProject(ctx, secret.ProjectID)
	if err != nil {
		return nil, err
	}
	info := c.resolveSecretInfo(ctx, edges)
	// Defence-in-depth: only consider edges whose BOTH endpoints actually live in the
	// focal secret's environment — independent of the add-time same-environment guard —
	// so the view can never surface a name from another environment the caller may not
	// be authorized on, even if a cross-environment edge were somehow present.
	edges = edgesWithinEnvironment(edges, info, secret.EnvironmentID)
	out := &SecretDependencies{SecretID: secretID, DependsOn: []DependencyEdge{}, Dependents: []DependencyEdge{}}
	for _, e := range edges {
		switch secretID {
		case e.DependentSecretID:
			out.DependsOn = append(out.DependsOn, DependencyEdge{ID: e.ID, SecretID: e.DependsOnSecretID, SecretName: info[e.DependsOnSecretID].name, Note: e.Note})
		case e.DependsOnSecretID:
			out.Dependents = append(out.Dependents, DependencyEdge{ID: e.ID, SecretID: e.DependentSecretID, SecretName: info[e.DependentSecretID].name, Note: e.Note})
		}
	}
	return out, nil
}

// GetSecretImpact returns the blast radius of rotating/changing a secret: every
// secret that transitively depends on it, with hop-distance, in breadth-first order.
func (c *KeyorixCore) GetSecretImpact(ctx context.Context, secretID uint) (*SecretImpact, error) {
	secret, err := c.requireSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	edges, err := c.storage.ListSecretDependenciesForProject(ctx, secret.ProjectID)
	if err != nil {
		return nil, err
	}
	info := c.resolveSecretInfo(ctx, edges)
	edges = edgesWithinEnvironment(edges, info, secret.EnvironmentID) // defence-in-depth, as in ListSecretDependencies
	affected := transitiveDependents(edges, secretID)
	out := &SecretImpact{SecretID: secretID, SecretName: secret.Name, Affected: make([]ImpactedSecret, 0, len(affected))}
	for _, a := range affected {
		out.Affected = append(out.Affected, ImpactedSecret{SecretID: a.id, SecretName: info[a.id].name, Depth: a.depth})
	}
	return out, nil
}

// GetProjectRotationOrder returns a safe rotation sequence for a project's dependency
// graph: each secret precedes any secret that depends on it. Only secrets that appear
// in the graph are ordered (standalone secrets can rotate at any time).
func (c *KeyorixCore) GetProjectRotationOrder(ctx context.Context, projectID uint) (*RotationOrder, error) {
	edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	// Rotation order is project-wide (authorized by a project-scoped grant that spans
	// all environments), so no per-environment filter here — but a soft-deleted secret
	// (ADR-033) must not appear in the order. Resolve names first, then drop any edge
	// incident to a secret that no longer resolves, so the graph follows the secret's
	// soft-delete/restore lifecycle (the env-scoped views filter the same way).
	info := c.resolveSecretInfo(ctx, edges)
	edges = edgesBetweenLiveSecrets(edges, info)
	order, ok := topologicalRotationOrder(edges)
	if !ok {
		// Defensive: cycles are rejected at add, so a remaining cycle is a data fault.
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorInternal", nil), "the dependency graph contains a cycle")
	}
	out := &RotationOrder{ProjectID: projectID, Order: make([]SecretRef, 0, len(order))}
	for _, id := range order {
		out.Order = append(out.Order, SecretRef{SecretID: id, SecretName: info[id].name})
	}
	return out, nil
}

// requireSecret loads a secret node and verifies it is an actual secret (not a folder)
// — the endpoints of a dependency must both be secrets.
func (c *KeyorixCore) requireSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	node, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: secret %d not found", i18n.T("ErrorNotFound", nil), id)
	}
	if !node.IsSecret {
		return nil, fmt.Errorf("%s: %d is not a secret", i18n.T("ErrorValidation", nil), id)
	}
	return node, nil
}

// secretInfo is the per-secret metadata the views need: its name and the environment
// it actually lives in (the latter is the authoritative value for the env filter).
type secretInfo struct {
	name string
	env  uint
}

// resolveSecretInfo builds an id→{name,env} map for every secret referenced by edges,
// so the views can show names and filter by real environment without an extra
// round-trip per row. A secret that no longer resolves is absent from the map (zero
// value), so it is treated as not in any caller's environment.
func (c *KeyorixCore) resolveSecretInfo(ctx context.Context, edges []*models.SecretDependency) map[uint]secretInfo {
	ids := make(map[uint]struct{})
	for _, e := range edges {
		ids[e.DependentSecretID] = struct{}{}
		ids[e.DependsOnSecretID] = struct{}{}
	}
	info := make(map[uint]secretInfo, len(ids))
	for id := range ids {
		if node, err := c.storage.GetSecret(ctx, id); err == nil {
			info[id] = secretInfo{name: node.Name, env: node.EnvironmentID}
		}
	}
	return info
}

// --- pure graph helpers (no storage; unit-testable in isolation) ---

// edgesWithinEnvironment keeps only edges whose BOTH endpoints actually live in the
// given environment, per the resolved info. Edges never cross environments (enforced at
// add), so this is defence-in-depth: it keeps the read paths safe even if a
// cross-environment edge were somehow present, because it checks the endpoints' real
// environments rather than trusting any field on the edge.
func edgesWithinEnvironment(edges []*models.SecretDependency, info map[uint]secretInfo, environmentID uint) []*models.SecretDependency {
	out := make([]*models.SecretDependency, 0, len(edges))
	for _, e := range edges {
		if info[e.DependentSecretID].env == environmentID && info[e.DependsOnSecretID].env == environmentID {
			out = append(out, e)
		}
	}
	return out
}

// edgesBetweenLiveSecrets keeps only edges whose BOTH endpoints resolved to a live
// secret (present in info). A soft-deleted endpoint does not resolve — GetSecret hides it
// (ADR-033) — so it is absent from info, dropping every edge incident to it. The edge
// rows are never mutated, so restoring the secret brings its edges back into the graph
// automatically. Used by the project-wide rotation order, which (unlike the env-scoped
// views) has no environment filter to exclude a deleted endpoint for it.
func edgesBetweenLiveSecrets(edges []*models.SecretDependency, info map[uint]secretInfo) []*models.SecretDependency {
	out := make([]*models.SecretDependency, 0, len(edges))
	for _, e := range edges {
		_, dependentLive := info[e.DependentSecretID]
		_, dependsOnLive := info[e.DependsOnSecretID]
		if dependentLive && dependsOnLive {
			out = append(out, e)
		}
	}
	return out
}

// dependentsAdjacency builds the reverse adjacency for impact analysis: for each
// secret, the set of secrets that directly depend on it (its dependents). Neighbour
// lists are sorted for deterministic traversal.
func dependentsAdjacency(edges []*models.SecretDependency) map[uint][]uint {
	adj := make(map[uint][]uint)
	for _, e := range edges {
		adj[e.DependsOnSecretID] = append(adj[e.DependsOnSecretID], e.DependentSecretID)
	}
	for k := range adj {
		sort.Slice(adj[k], func(i, j int) bool { return adj[k][i] < adj[k][j] })
	}
	return adj
}

// dependencyReachable reports whether `to` is reachable from `from` following
// depends-on edges (from depends on … depends on to). Used to detect cycles before
// adding an edge.
func dependencyReachable(edges []*models.SecretDependency, from, to uint) bool {
	adj := make(map[uint][]uint)
	for _, e := range edges {
		adj[e.DependentSecretID] = append(adj[e.DependentSecretID], e.DependsOnSecretID)
	}
	seen := map[uint]bool{from: true}
	stack := []uint{from}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, next := range adj[n] {
			if next == to {
				return true
			}
			if !seen[next] {
				seen[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}

type impacted struct {
	id    uint
	depth int
}

// transitiveDependents returns every secret that transitively depends on secretID, in
// breadth-first order with the shortest hop-distance. Excludes secretID itself.
func transitiveDependents(edges []*models.SecretDependency, secretID uint) []impacted {
	adj := dependentsAdjacency(edges)
	seen := map[uint]bool{secretID: true}
	out := []impacted{}
	queue := []impacted{{id: secretID, depth: 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range adj[cur.id] {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			out = append(out, impacted{id: dep, depth: cur.depth + 1})
			queue = append(queue, impacted{id: dep, depth: cur.depth + 1})
		}
	}
	return out
}

// topologicalRotationOrder returns the secrets in a project's dependency graph in a
// safe rotation order — each secret before any that depends on it — using Kahn's
// algorithm with deterministic tie-breaking (ascending secret id). ok is false if a
// cycle prevents a complete ordering (should not happen: cycles are rejected at add).
func topologicalRotationOrder(edges []*models.SecretDependency) (order []uint, ok bool) {
	// Prerequisite graph: rotate a dependency before its dependent, so an edge
	// (dependent depends on dependsOn) means dependsOn → dependent must precede.
	adj := make(map[uint][]uint) // dependsOn → its dependents
	indeg := make(map[uint]int)  // count of prerequisites (dependencies) per node
	nodes := make(map[uint]struct{})
	for _, e := range edges {
		adj[e.DependsOnSecretID] = append(adj[e.DependsOnSecretID], e.DependentSecretID)
		indeg[e.DependentSecretID]++
		nodes[e.DependentSecretID] = struct{}{}
		nodes[e.DependsOnSecretID] = struct{}{}
	}
	// Seed the queue with nodes that depend on nothing, smallest id first.
	ready := []uint{}
	for n := range nodes {
		if indeg[n] == 0 {
			ready = append(ready, n)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i] < ready[j] })

	order = make([]uint, 0, len(nodes))
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		order = append(order, n)
		next := append([]uint(nil), adj[n]...)
		sort.Slice(next, func(i, j int) bool { return next[i] < next[j] })
		for _, m := range next {
			indeg[m]--
			if indeg[m] == 0 {
				// Insert keeping `ready` sorted so the output is deterministic.
				pos := sort.Search(len(ready), func(i int) bool { return ready[i] >= m })
				ready = append(ready, 0)
				copy(ready[pos+1:], ready[pos:])
				ready[pos] = m
			}
		}
	}
	return order, len(order) == len(nodes)
}
