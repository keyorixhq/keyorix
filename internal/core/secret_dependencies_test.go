package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// edge is a terse constructor for the pure-helper tests.
func edge(dependent, dependsOn uint) *models.SecretDependency {
	return &models.SecretDependency{DependentSecretID: dependent, DependsOnSecretID: dependsOn}
}

func TestDependencyReachable(t *testing.T) {
	// 1→2→3 (1 depends on 2 depends on 3), plus 4→2.
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 3), edge(4, 2)}
	assert.True(t, dependencyReachable(edges, 1, 3), "1 transitively depends on 3")
	assert.True(t, dependencyReachable(edges, 1, 2))
	assert.False(t, dependencyReachable(edges, 3, 1), "3 does not depend on 1")
	assert.True(t, dependencyReachable(edges, 4, 3), "4→2→3 reachable")
	assert.False(t, dependencyReachable(edges, 2, 4), "2 does not reach 4")
}

func TestTransitiveDependents(t *testing.T) {
	// 3 is depended on by 2 and 4; 2 is depended on by 1. So rotating 3 impacts 2,4 (depth1) then 1 (depth2).
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 3), edge(4, 3)}
	got := transitiveDependents(edges, 3)
	require.Len(t, got, 3)
	// BFS order: depth-1 dependents of 3 first (2,4 sorted), then 1.
	assert.Equal(t, uint(2), got[0].id)
	assert.Equal(t, 1, got[0].depth)
	assert.Equal(t, uint(4), got[1].id)
	assert.Equal(t, 1, got[1].depth)
	assert.Equal(t, uint(1), got[2].id)
	assert.Equal(t, 2, got[2].depth)

	// A leaf nobody depends on has no impact.
	assert.Empty(t, transitiveDependents(edges, 1))
}

func TestTopologicalRotationOrder(t *testing.T) {
	// Diamond: 1 depends on 2 and 3; both 2 and 3 depend on 4.
	// Safe rotation = dependencies first: 4 before {2,3} before 1.
	edges := []*models.SecretDependency{edge(1, 2), edge(1, 3), edge(2, 4), edge(3, 4)}
	order, ok := topologicalRotationOrder(edges)
	require.True(t, ok)
	require.Equal(t, []uint{4, 2, 3, 1}, order, "4 first, then 2,3 (sorted), then 1")

	// Determinism: same input → same order.
	order2, _ := topologicalRotationOrder(edges)
	assert.Equal(t, order, order2)
}

func TestTopologicalRotationOrderDetectsCycle(t *testing.T) {
	// A hand-built cycle 1→2→1 (the add path prevents this; the sort must still flag it).
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 1)}
	_, ok := topologicalRotationOrder(edges)
	assert.False(t, ok, "a cyclic graph yields no complete ordering")
}

// --- integration tests against a real in-memory store ---

func newDepCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretDependency{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}))
	// Live parent projects (1, 2) + environment (1): RestoreSecret refuses to restore a
	// secret into a soft-deleted parent, so the dependency-cascade tests need them present.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	now := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkSecret inserts a secret node (environment 1) and returns its id.
func mkSecret(t *testing.T, db *gorm.DB, projectID uint, name string) uint {
	return mkSecretEnv(t, db, projectID, 1, name)
}

// mkSecretEnv inserts a secret node in a specific environment and returns its id.
func mkSecretEnv(t *testing.T, db *gorm.DB, projectID, environmentID uint, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: projectID, EnvironmentID: environmentID, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

func TestAddSecretDependency_Validation(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	dbPass := mkSecret(t, db, 1, "db-password")
	appTok := mkSecret(t, db, 1, "app-token")
	otherProj := mkSecret(t, db, 2, "other-secret")

	t.Run("happy path", func(t *testing.T) {
		got, err := c.AddSecretDependency(ctx, 10, appTok, dbPass, "app token derives from db password")
		require.NoError(t, err)
		assert.Equal(t, appTok, got.DependentSecretID)
		assert.Equal(t, dbPass, got.DependsOnSecretID)
		assert.Equal(t, uint(1), got.ProjectID)
	})

	t.Run("self-dependency rejected", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, 10, dbPass, dbPass, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "itself")
	})

	t.Run("cross-project rejected", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, 10, appTok, otherProj, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "same project")
	})

	t.Run("duplicate rejected", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, 10, appTok, dbPass, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("cycle rejected", func(t *testing.T) {
		// appTok already depends on dbPass; making dbPass depend on appTok is a cycle.
		_, err := c.AddSecretDependency(ctx, 10, dbPass, appTok, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cycle")
	})

	t.Run("missing dependency target rejected with an opaque error (no existence oracle)", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, 10, appTok, 9999, "")
		require.Error(t, err)
		// Must NOT reveal whether 9999 exists / what it is — same message as a cross-scope
		// target, so the caller can't enumerate secret IDs across scopes.
		assert.NotContains(t, err.Error(), "9999")
		assert.Contains(t, err.Error(), "same project and environment")
	})
}

// A dependency must stay within one environment — authorization is environment-
// granular, so a cross-environment edge would let an env-scoped caller reference a
// secret in another environment of the same project.
func TestAddSecretDependency_CrossEnvironmentRejected(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	staging := mkSecretEnv(t, db, 1, 1, "app-token")     // project 1, env 1
	prod := mkSecretEnv(t, db, 1, 2, "prod-db-password") // project 1, env 2
	_, err := c.AddSecretDependency(ctx, 10, staging, prod, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment")
}

// Removal is scoped to the focal secret: the edge must reference it, so a caller
// authorized only on another secret cannot delete an unrelated edge.
func TestRemoveSecretDependency_RequiresFocalReference(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	a := mkSecret(t, db, 1, "a")
	b := mkSecret(t, db, 1, "b")
	other := mkSecret(t, db, 1, "other")
	e, err := c.AddSecretDependency(ctx, 1, a, b, "")
	require.NoError(t, err)

	// 'other' is not part of edge a→b → removal scoped to 'other' is rejected.
	err = c.RemoveSecretDependency(ctx, 1, other, e.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not reference")

	// Scoped to the dependent secret 'a' → allowed.
	require.NoError(t, c.RemoveSecretDependency(ctx, 1, a, e.ID))
}

// Defence-in-depth: even if a cross-environment edge is somehow present (here inserted
// directly, bypassing the add guard), the read paths must not surface the other
// environment's secret — they filter to the focal secret's environment independently.
func TestSecretDependencyReadsFilterByEnvironment(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	envA := mkSecretEnv(t, db, 1, 1, "env-a-secret")
	envB := mkSecretEnv(t, db, 1, 2, "env-b-secret")
	// Forge a cross-environment edge (env-A depends on env-B) directly in storage,
	// bypassing the add-time guard. The endpoints span two environments.
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID: 1, DependentSecretID: envA, DependsOnSecretID: envB,
	}).Error)

	deps, err := c.ListSecretDependencies(ctx, envA)
	require.NoError(t, err)
	assert.Empty(t, deps.DependsOn, "a cross-environment edge must not appear in env-A's view")

	impact, err := c.GetSecretImpact(ctx, envB)
	require.NoError(t, err)
	assert.Empty(t, impact.Affected, "impact from env-B must not cross into env-A via a forged edge")
}

func TestSecretDependencyImpactAndOrderAndRemove(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	root := mkSecret(t, db, 1, "root-ca")
	mid := mkSecret(t, db, 1, "intermediate")
	leaf := mkSecret(t, db, 1, "service-cert")

	// service-cert depends on intermediate depends on root-ca.
	_, err := c.AddSecretDependency(ctx, 1, mid, root, "")
	require.NoError(t, err)
	e2, err := c.AddSecretDependency(ctx, 1, leaf, mid, "")
	require.NoError(t, err)

	// Impact of rotating root-ca: intermediate (depth1) then service-cert (depth2).
	impact, err := c.GetSecretImpact(ctx, root)
	require.NoError(t, err)
	require.Len(t, impact.Affected, 2)
	assert.Equal(t, "intermediate", impact.Affected[0].SecretName)
	assert.Equal(t, 1, impact.Affected[0].Depth)
	assert.Equal(t, "service-cert", impact.Affected[1].SecretName)
	assert.Equal(t, 2, impact.Affected[1].Depth)

	// Rotation order: root-ca, intermediate, service-cert.
	order, err := c.GetProjectRotationOrder(ctx, 1)
	require.NoError(t, err)
	require.Len(t, order.Order, 3)
	assert.Equal(t, []string{"root-ca", "intermediate", "service-cert"},
		[]string{order.Order[0].SecretName, order.Order[1].SecretName, order.Order[2].SecretName})

	// List from the middle secret: depends on root, depended on by leaf.
	view, err := c.ListSecretDependencies(ctx, mid)
	require.NoError(t, err)
	require.Len(t, view.DependsOn, 1)
	assert.Equal(t, "root-ca", view.DependsOn[0].SecretName)
	require.Len(t, view.Dependents, 1)
	assert.Equal(t, "service-cert", view.Dependents[0].SecretName)

	// Remove the leaf→mid edge; impact of root shrinks to just intermediate.
	require.NoError(t, c.RemoveSecretDependency(ctx, 1, leaf, e2.ID))
	impact, err = c.GetSecretImpact(ctx, root)
	require.NoError(t, err)
	require.Len(t, impact.Affected, 1)
	assert.Equal(t, "intermediate", impact.Affected[0].SecretName)
}

// --- concurrency: #260 ---

// TestAddSecretDependency_ConcurrentRaceCannotPersistACycle empirically reproduces
// #260: two goroutines racing to add A→B and B→A in the same project must never
// BOTH succeed — that would persist a 2-node cycle that GetProjectRotationOrder
// (and, transitively, the deployment-wide rotation-plan roll-up) hard-errors on
// forever, with nothing else able to detect or heal the stuck edge. Repeated across
// many fresh secret pairs on a single-connection DB (forcing the two goroutines'
// individual statements to interleave through the same connection, the same
// technique that originally reproduced the race deterministically) so the narrow
// pre-fix race window is reliably exercised, not just occasionally hit.
func TestAddSecretDependency_ConcurrentRaceCannotPersistACycle(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	const iterations = 50
	for i := 0; i < iterations; i++ {
		a := mkSecret(t, db, 1, fmt.Sprintf("a-%d", i))
		b := mkSecret(t, db, 1, fmt.Sprintf("b-%d", i))

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, results[0] = c.AddSecretDependency(ctx, 1, a, b, "")
		}()
		go func() {
			defer wg.Done()
			<-start
			_, results[1] = c.AddSecretDependency(ctx, 1, b, a, "")
		}()
		close(start)
		wg.Wait()

		successes := 0
		for _, e := range results {
			if e == nil {
				successes++
			}
		}
		require.Equal(t, 1, successes,
			"iteration %d: exactly one of A→B / B→A must win the race — both winning would persist a cycle, both losing would lose a legitimate edge", i)

		// No cycle was persisted: rotation ordering for the project must still succeed.
		_, err := c.GetProjectRotationOrder(ctx, 1)
		require.NoError(t, err, "iteration %d: no lingering cycle in the persisted graph", i)
	}
}
