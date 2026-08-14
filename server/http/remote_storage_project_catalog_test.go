package http

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForProjectCatalog builds the standard #452/#507-style
// two-server harness (see remote_storage_groups_test.go's identical helper): an
// "upstream" exercised through the REAL production NewRouter/handlers (including the
// new /api/v1/system/projects* routes, server/http/handlers/project_catalog_proxy.go),
// and a "downstream" *core.KeyorixCore configured with storage.type: remote
// (ADR-049), pointed at "upstream" over real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForProjectCatalog(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return upstream, downstream
}

// TestRemoteStorageProject_ListGetUpdate_RealServer proves the read/update fix: a
// project created directly on the upstream (RemoteStorage has no CreateProject —
// that stays an intentional stub, see remote_rbac.go) is listed, fetched, and
// updated correctly via the DOWNSTREAM's RemoteStorage, all against a real router,
// not a protocol mock.
func TestRemoteStorageProject_ListGetUpdate_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	created, err := upstream.CreateProject(ctx, "catalog-project", "initial description")
	require.NoError(t, err)

	// ListProjects via the downstream sees the real upstream row.
	all, err := downstream.Storage().ListProjects(ctx)
	require.NoError(t, err)
	found := false
	for _, p := range all {
		if p.ID == created.ID {
			found = true
			assert.Equal(t, "catalog-project", p.Name)
		}
	}
	assert.True(t, found, "ListProjects must include the real upstream project")

	// ListProjectsWithCounts via the downstream.
	withCounts, err := downstream.Storage().ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	foundCounts := false
	for _, p := range withCounts {
		if p.ID == created.ID {
			foundCounts = true
			// CreateProject seeds default environments, so this must be > 0.
			assert.Greater(t, p.EnvironmentCount, int64(0))
		}
	}
	assert.True(t, foundCounts, "ListProjectsWithCounts must include the real upstream project")

	// GetProject via the downstream round-trips correctly.
	fetched, err := downstream.Storage().GetProject(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, "catalog-project", fetched.Name)
	assert.Equal(t, "initial description", fetched.Description)

	// UpdateProject via the downstream persists on the upstream.
	fetched.Name = "renamed-project"
	fetched.Description = "updated description"
	fetched.RequireMFA = true
	updated, err := downstream.Storage().UpdateProject(ctx, fetched)
	require.NoError(t, err)
	assert.Equal(t, "renamed-project", updated.Name)
	assert.True(t, updated.RequireMFA)

	direct, err := upstream.Storage().GetProject(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "renamed-project", direct.Name, "the update must be a REAL upstream write")
	assert.Equal(t, "updated description", direct.Description)
	assert.True(t, direct.RequireMFA)
}

// TestRemoteStorageProject_GetNotFound_RealServer proves a clean not-found error for
// a nonexistent project ID.
func TestRemoteStorageProject_GetNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetProject(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageProject_DeleteIfEmpty_And_Force_RealServer proves the #528
// DeleteProjectIfEmpty fix end to end: a project with a live secret blocks a
// force=false delete (reporting the real blocking count), while force=true
// (plain DeleteProject) cascades over it regardless — both via the downstream's
// RemoteStorage against a real upstream server.
func TestRemoteStorageProject_DeleteIfEmpty_And_Force_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	project, err := upstream.CreateProject(ctx, "delete-guard-project", "")
	require.NoError(t, err)
	envs, err := upstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "CreateProject must have seeded default environments")
	envID := envs[0].ID

	_, err = upstream.Storage().CreateSecret(ctx, &models.SecretNode{
		Name:          "guard-secret",
		ProjectID:     project.ID,
		EnvironmentID: envID,
		IsSecret:      true,
	})
	require.NoError(t, err)

	// DeleteProjectIfEmpty via the downstream must reject: the project has a live
	// secret, reporting the real blocking count (not silently cascading over it).
	blocking, err := downstream.Storage().DeleteProjectIfEmpty(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, blocking, "DeleteProjectIfEmpty must report the real blocking secret count")

	direct, err := upstream.Storage().GetProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, project.ID, direct.ID, "a rejected guard must leave the project live")

	// DeleteProject (the plain, unconditional cascade — the force=true path) via the
	// downstream cascades over the secret regardless.
	require.NoError(t, downstream.Storage().DeleteProject(ctx, project.ID))
	_, err = upstream.Storage().GetProject(ctx, project.ID)
	require.Error(t, err, "a soft-deleted project must no longer be readable as active")

	// RestoreProject via the downstream brings back the project AND the cascaded
	// secret/environment.
	restoredEnvs, restoredSecrets, err := downstream.Storage().RestoreProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Positive(t, restoredEnvs)
	assert.Equal(t, 1, restoredSecrets)
	restored, err := upstream.Storage().GetProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, "delete-guard-project", restored.Name, "restore must bring back the SAME row")
}

// TestRemoteStorageProject_DeleteIfEmpty_EmptyProjectSucceeds_RealServer proves the
// success path: an empty project's force=false delete actually deletes (reports
// blockingSecretCount 0), matching DeleteProject(force=false)'s LocalStorage
// behavior exactly.
func TestRemoteStorageProject_DeleteIfEmpty_EmptyProjectSucceeds_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	project, err := upstream.CreateProject(ctx, "empty-delete-project", "")
	require.NoError(t, err)

	blocking, err := downstream.Storage().DeleteProjectIfEmpty(ctx, project.ID)
	require.NoError(t, err)
	assert.Zero(t, blocking)

	_, err = upstream.Storage().GetProject(ctx, project.ID)
	require.Error(t, err, "an empty project's force=false delete must actually delete it")
}

// TestRemoteStorageProject_DeleteIfEmpty_ConcurrentRaceIsSerialized_RealServer is the
// concurrency test for the #528 atomicity fix: N goroutines on the SAME downstream
// (storage.type: remote) core.KeyorixCore race to DeleteProjectIfEmpty the SAME empty
// project concurrently. Before this fix, core.DeleteProject's force=false guard ran
// as a WithTransaction-wrapped ListSecrets-then-DeleteProject pair — safe under
// LocalStorage's real transaction, but WithTransaction is a no-op passthrough over
// HTTP for RemoteStorage, so under storage.type: remote a naive proxy of that same
// pair could let TWO racers both observe "empty" and both attempt the cascade,
// double-processing the delete (e.g. double-counting the #369 dynamic-secret-lease
// revocation, or racing the #311 restored-count audit math). DeleteProjectIfEmpty
// folds the guard and the cascade into ONE atomic call, so exactly one racer's
// cascade must ever actually commit — proven here against a REAL upstream server,
// not a mock.
func TestRemoteStorageProject_DeleteIfEmpty_ConcurrentRaceIsSerialized_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForProjectCatalog(t)
	ctx := context.Background()

	project, err := upstream.CreateProject(ctx, "race-delete-project", "")
	require.NoError(t, err)

	const n = 8
	var wg sync.WaitGroup
	blockingCounts := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			blockingCounts[i], errs[i] = downstream.Storage().DeleteProjectIfEmpty(ctx, project.ID)
		}(i)
	}
	wg.Wait()

	successes := 0
	for i := 0; i < n; i++ {
		if errs[i] == nil {
			successes++
			assert.Zero(t, blockingCounts[i], "a successful racer must report zero blocking secrets")
		} else {
			assert.Contains(t, errs[i].Error(), "not found",
				"a losing racer must see a clean 'not found' (the row the winner already soft-deleted), not a corrupted partial state")
		}
	}
	assert.Equal(t, 1, successes, "exactly one racer's cascade must actually commit — no double-delete, no double-processing")

	direct, err := upstream.Storage().GetProject(ctx, project.ID)
	require.Error(t, err, "the project must end up soft-deleted exactly once")
	_ = direct
}
