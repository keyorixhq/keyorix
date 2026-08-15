package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamForSecretDependencies builds the standard #452/#507-style harness: an
// "upstream" exercised through the REAL production NewRouter/handlers (including the
// new /api/v1/system/secret-dependencies routes, server/http/handlers/
// secret_dependencies_proxy.go) and returns an httptest.Server plus the admin token a
// downstream RemoteStorage client needs to reach it.
func newUpstreamForSecretDependencies(t *testing.T) (upstream *core.KeyorixCore, srv *httptest.Server, token string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	token = createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	router, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	srv = httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return upstream, srv, token
}

// newDownstreamRemoteStorage points a fresh *core.KeyorixCore, backed by
// store.RemoteStorage, at the given upstream test server.
func newDownstreamRemoteStorage(t *testing.T, srv *httptest.Server, token string) *core.KeyorixCore {
	t.Helper()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        srv.URL,
		APIKey:         token,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	return core.NewKeyorixCore(rs)
}

// TestRemoteStorageSecretDependencies_CreateGetListDelete_RealServer proves the fix for
// CreateSecretDependency/GetSecretDependency/ListSecretDependenciesForProject/
// ListSecretDependenciesForProjectForUpdate/DeleteSecretDependency: an edge is
// genuinely persisted on the upstream via the downstream's RemoteStorage, fetchable by
// ID, listed both ways, and removable — all via storage.type: remote against a real
// router, not a protocol mock.
func TestRemoteStorageSecretDependencies_CreateGetListDelete_RealServer(t *testing.T) {
	upstream, srv, token := newUpstreamForSecretDependencies(t)
	downstream := newDownstreamRemoteStorage(t, srv, token)
	ctx := context.Background()

	created, err := downstream.Storage().CreateSecretDependency(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 501, DependsOnSecretID: 502, Note: "app token derives from db password", CreatedBy: 10,
	})
	require.NoError(t, err, "creating a secret dependency must succeed via storage.type: remote")
	require.NotZero(t, created.ID, "the upstream must assign a real ID")
	assert.Equal(t, uint(501), created.DependentSecretID)
	assert.Equal(t, uint(502), created.DependsOnSecretID)

	// A REAL row on the upstream's own storage, not just "the call didn't error".
	direct, err := upstream.Storage().GetSecretDependency(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "app token derives from db password", direct.Note)
	assert.Equal(t, uint(10), direct.CreatedBy)

	// GetSecretDependency via the downstream round-trips every field.
	fetched, err := downstream.Storage().GetSecretDependency(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, created.Note, fetched.Note)
	assert.Equal(t, created.ProjectID, fetched.ProjectID)

	// A second edge, then list both back via the downstream's
	// ListSecretDependenciesForProject / ListSecretDependenciesForProjectForUpdate.
	second, err := downstream.Storage().CreateSecretDependency(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 503, DependsOnSecretID: 501,
	})
	require.NoError(t, err)

	rows, err := downstream.Storage().ListSecretDependenciesForProject(ctx, 1)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	rowsForUpdate, err := downstream.Storage().ListSecretDependenciesForProjectForUpdate(ctx, 1)
	require.NoError(t, err)
	require.Len(t, rowsForUpdate, 2)

	// DeleteSecretDependency via the downstream removes it from the upstream's own
	// storage.
	require.NoError(t, downstream.Storage().DeleteSecretDependency(ctx, second.ID))
	_, err = upstream.Storage().GetSecretDependency(ctx, second.ID)
	require.Error(t, err, "the deleted edge must no longer exist directly on the upstream")

	remaining, err := downstream.Storage().ListSecretDependenciesForProject(ctx, 1)
	require.NoError(t, err)
	require.Len(t, remaining, 1)
	assert.Equal(t, created.ID, remaining[0].ID)
}

// TestRemoteStorageSecretDependencies_GetNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a nonexistent edge ID.
func TestRemoteStorageSecretDependencies_GetNotFound_RealServer(t *testing.T) {
	_, srv, token := newUpstreamForSecretDependencies(t)
	downstream := newDownstreamRemoteStorage(t, srv, token)

	_, err := downstream.Storage().GetSecretDependency(context.Background(), 999999)
	require.Error(t, err)
}

// TestRemoteStorageSecretDependencies_Exclusive_DuplicateAndCycleRejected proves
// CreateSecretDependencyExclusive's wire-code translation (#511-style): the upstream's
// 409/400 rejection round-trips back into the exact
// storage.ErrDuplicateSecretDependency / storage.ErrSecretDependencyCycle sentinels,
// not an opaque error, so AddSecretDependency's errors.Is checks
// (internal/core/secret_dependencies.go) still work against storage.type: remote.
func TestRemoteStorageSecretDependencies_Exclusive_DuplicateAndCycleRejected(t *testing.T) {
	_, srv, token := newUpstreamForSecretDependencies(t)
	downstream := newDownstreamRemoteStorage(t, srv, token)
	ctx := context.Background()

	created, err := downstream.Storage().CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 601, DependsOnSecretID: 602,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	// Exact duplicate pair.
	_, err = downstream.Storage().CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 601, DependsOnSecretID: 602,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrDuplicateSecretDependency),
		"the upstream's duplicate rejection must survive as the exact sentinel, not an opaque error: %v", err)

	// Reverse edge would close a 2-node cycle.
	_, err = downstream.Storage().CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 602, DependsOnSecretID: 601,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrSecretDependencyCycle),
		"the upstream's cycle rejection must survive as the exact sentinel, not an opaque error: %v", err)
}

// TestRemoteStorageSecretDependencies_ConcurrentRace_NoCycleAcrossTwoDownstreams is the
// cross-process analogue of internal/core's
// TestAddSecretDependency_ConcurrentRaceCannotPersistACycle (#260): TWO INDEPENDENT
// *store.RemoteStorage clients (standing in for two downstream server replicas — e.g.
// two separate *core.KeyorixCore instances, each with its OWN process-local
// secretDependencyMu that cannot serialize across them) race to persist reciprocal
// edges A→B / B→A in the same project against the SAME upstream, via
// CreateSecretDependencyExclusive directly (the raw storage primitive
// AddSecretDependency calls, exercised here without core's own project/secret
// authorization plumbing, which is a separate, pre-existing concern — mirroring
// buildDynamicSecretConfig's documented precedent in
// remote_storage_dynamic_secrets_test.go for testing the storage-primitive proxy layer
// directly rather than the full core happy path).
//
// Before this fix (a caller-orchestrated ListSecretDependenciesForProjectForUpdate +
// CreateSecretDependency sequence, with RemoteStorage.WithTransaction a no-op
// passthrough), nothing would have prevented both requests from observing "no cycle"
// and both succeeding, persisting a 2-node cycle. With CreateSecretDependencyExclusive,
// the upstream's own LocalStorage transaction serializes the two concurrent HTTP
// requests, so exactly one must win — proving the fix closes the gap the interface doc
// describes, not just the same-process case the mutex already covered.
func TestRemoteStorageSecretDependencies_ConcurrentRace_NoCycleAcrossTwoDownstreams(t *testing.T) {
	_, srv, token := newUpstreamForSecretDependencies(t)
	ctx := context.Background()

	const iterations = 8
	for i := 0; i < iterations; i++ {
		a := uint(2000 + i*2)
		b := uint(2000 + i*2 + 1)

		// Fresh RemoteStorage clients each iteration: every pair has exactly one
		// "loser" that gets an expected 400/409 rejection, and the client's circuit
		// breaker (internal/storage/remote/client.go) opens after 5 CONSECUTIVE
		// failures regardless of whether they were expected application-level
		// rejections or genuine transport failures (a separate, pre-existing
		// design point, out of scope here) — reusing one client across many
		// iterations would eventually trip it on the same side repeatedly,
		// masking the real property this test checks with an unrelated
		// "circuit breaker is open" error.
		downstreamA := newDownstreamRemoteStorage(t, srv, token)
		downstreamB := newDownstreamRemoteStorage(t, srv, token)

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, results[0] = downstreamA.Storage().CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
				ProjectID: 1, DependentSecretID: a, DependsOnSecretID: b,
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, results[1] = downstreamB.Storage().CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
				ProjectID: 1, DependentSecretID: b, DependsOnSecretID: a,
			})
		}()
		close(start)
		wg.Wait()

		successes := 0
		for _, e := range results {
			if e == nil {
				successes++
			} else {
				assert.True(t, errors.Is(e, coreStorage.ErrDuplicateSecretDependency) || errors.Is(e, coreStorage.ErrSecretDependencyCycle),
					"iteration %d: the loser must fail with a recognised sentinel, not an opaque error: %v", i, e)
			}
		}
		require.Equal(t, 1, successes,
			"iteration %d: exactly one of A→B / B→A must win the race across two independent downstream RemoteStorage clients — both winning would persist a cycle on the shared upstream", i)
	}
}
