package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// newUpstreamDownstreamForBreakGlass builds the standard #507/#511-style
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/break-glass routes,
// server/http/handlers/break_glass_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage. Also returns the upstream's
// base URL/token so concurrency tests can mint additional, independent
// RemoteStorage clients against the SAME upstream server (see
// newBreakGlassRemoteClient).
func newUpstreamDownstreamForBreakGlass(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore, projectID uint, baseURL, apiKey string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	downstream = newBreakGlassRemoteClient(t, upstreamSrv.URL, upstreamToken)

	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "Break Glass Test Project", "")
	require.NoError(t, err)
	return upstream, downstream, project.ID, upstreamSrv.URL, upstreamToken
}

// newBreakGlassRemoteClient builds a fresh *core.KeyorixCore backed by its OWN
// store.RemoteStorage/HTTPClient instance pointed at baseURL. Used by the
// concurrency tests below to give EACH concurrent racer its own client (and
// thus its own independent circuit breaker / failure counter,
// internal/storage/remote.HTTPClient): the client's circuit breaker treats
// every 4xx/5xx response (including a genuine, expected 409 Conflict from a
// losing racer, #501) as a "failure" and trips after 5 consecutive ones on a
// SHARED client — a real concern unique to this subsystem, since (unlike
// #507's UpdateProjectInvitation, which reports a losing racer via a plain
// `{"updated": false}` 200) CreateBreakGlassActivation/
// RevokeBreakGlassActivation communicate a losing racer as a genuine error
// even against LocalStorage (storage.ErrBreakGlassAlreadyActive/
// ErrBreakGlassNotActive), so a client-side circuit breaker is not something
// this proxy can or should paper over — it is exactly the same behavior a
// downstream server's OWN client would exhibit in production if many break-glass
// activations for the same project+user raced in a short window. Giving each
// simulated caller its own client isolates that (expected, orthogonal)
// resilience behavior from the atomicity property this test exists to prove.
func newBreakGlassRemoteClient(t *testing.T, baseURL, apiKey string) *core.KeyorixCore {
	t.Helper()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        baseURL,
		APIKey:         apiKey,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	return core.NewKeyorixCore(rs)
}

// buildActiveBreakGlassActivation mirrors what internal/core.ActivateBreakGlass
// computes before calling storage.CreateBreakGlassActivation — a fully-built
// active activation row — WITHOUT going through ActivateBreakGlass itself (which
// additionally requires the calling server's own break-glass policy/RBAC/
// project-affiliation setup, out of this finding's raw storage-primitive scope,
// mirroring buildDynamicSecretConfig's/buildPendingInvitation's precedent).
func buildActiveBreakGlassActivation(now time.Time, projectID, userID uint) *models.BreakGlassActivation {
	expiresAt := now.Add(4 * time.Hour)
	return &models.BreakGlassActivation{
		ProjectID:     projectID,
		UserID:        userID,
		RoleID:        3,
		RoleName:      "editor",
		Justification: "prod incident #42",
		State:         core.BreakGlassActive,
		ExpiresAt:     &expiresAt,
		CreatedAt:     now,
	}
}

// TestRemoteStorageBreakGlass_CreateGetListUpdate_RealServer proves the fix for
// CreateBreakGlassActivation/GetBreakGlassActivation/ListBreakGlassActivations/
// UpdateBreakGlassActivation: an activation is genuinely persisted on the
// upstream server via the DOWNSTREAM's RemoteStorage, fetchable by ID, listed,
// and updatable — all via storage.type: remote against a real router, not a
// protocol mock.
func TestRemoteStorageBreakGlass_CreateGetListUpdate_RealServer(t *testing.T) {
	upstream, downstream, projectID, _, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()

	act, err := downstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 10))
	require.NoError(t, err, "creating a break-glass activation must succeed via storage.type: remote")
	require.NotZero(t, act.ID, "the upstream must assign a real ID")
	assert.Equal(t, "editor", act.RoleName)
	assert.Equal(t, core.BreakGlassActive, act.State)
	assert.Equal(t, projectID, act.ProjectID)
	assert.EqualValues(t, 10, act.UserID)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, "prod incident #42", direct.Justification)

	// GetBreakGlassActivation via the downstream (RemoteStorage) round-trips
	// every field correctly.
	fetched, err := downstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, act.ID, fetched.ID)
	assert.Equal(t, act.Justification, fetched.Justification)
	require.NotNil(t, fetched.ExpiresAt)
	assert.WithinDuration(t, *act.ExpiresAt, *fetched.ExpiresAt, time.Second)

	// A second activation for a DIFFERENT user, then list both back via the
	// downstream's ListBreakGlassActivations.
	_, err = downstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 11))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListBreakGlassActivations(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	userIDs := map[uint]bool{}
	for _, r := range rows {
		userIDs[r.UserID] = true
	}
	assert.True(t, userIDs[10])
	assert.True(t, userIDs[11])

	// UpdateBreakGlassActivation persists a change via the downstream.
	fetched.Justification = "updated justification text"
	require.NoError(t, downstream.Storage().UpdateBreakGlassActivation(ctx, fetched))
	reFetched, err := upstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated justification text", reFetched.Justification, "the update must be visible directly on the upstream's own storage")
}

// TestRemoteStorageBreakGlass_GetNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a nonexistent activation ID.
func TestRemoteStorageBreakGlass_GetNotFound_RealServer(t *testing.T) {
	_, downstream, _, _, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetBreakGlassActivation(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageBreakGlass_CreateRejectsSecondActiveForSameProjectUser_RealServer
// proves CreateBreakGlassActivationProxy's 409/BREAK_GLASS_ALREADY_ACTIVE
// wire-code translation round-trips correctly: a second concurrent-active
// activation for the SAME (project_id, user_id) is rejected with the same
// storage.ErrBreakGlassAlreadyActive sentinel core.ActivateBreakGlass's
// errors.Is check depends on — not an opaque "create failed" error — even though
// this now went over a real HTTP hop instead of a direct in-process call.
func TestRemoteStorageBreakGlass_CreateRejectsSecondActiveForSameProjectUser_RealServer(t *testing.T) {
	_, downstream, projectID, _, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()

	first, err := downstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 42))
	require.NoError(t, err)
	assert.NotZero(t, first.ID)

	_, err = downstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 42))
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrBreakGlassAlreadyActive), "got %v", err)
}

// TestRemoteStorageBreakGlass_RevokeThenRevokeAgainFails_RealServer proves
// RevokeBreakGlassActivationProxy's conditional `WHERE state = 'active'` update
// (and its 409/BREAK_GLASS_NOT_ACTIVE wire-code translation) round-trips
// correctly: revoking an already-revoked activation cleanly fails with
// storage.ErrBreakGlassNotActive, the sentinel core.RevokeBreakGlass's
// errors.Is check depends on.
func TestRemoteStorageBreakGlass_RevokeThenRevokeAgainFails_RealServer(t *testing.T) {
	_, downstream, projectID, _, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()

	act, err := downstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 7))
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().RevokeBreakGlassActivation(ctx, act.ID, 1, time.Now()))

	final, err := downstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassRevoked, final.State)

	err = downstream.Storage().RevokeBreakGlassActivation(ctx, act.ID, 1, time.Now())
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrBreakGlassNotActive), "got %v", err)
}

// TestRemoteStorageBreakGlass_ConcurrentActivationRace_RealServer is the critical
// #519 test (mirroring #507's TestRemoteStorageInvitation_ConcurrentAcceptRace_
// RealServer and #511's project-membership race test): it fires N concurrent
// "activate" requests for the SAME (project_id, user_id) over real HTTP against
// the real upstream router, and asserts EXACTLY ONE succeeds — proving
// CreateBreakGlassActivationProxy's real DB-level partial-unique-index race gate
// (local_break_glass.go's `OnConflict{DoNothing: true}` insert, backing
// uniq_break_glass_active_project_user — docs/security/BUGS.md #104, PR #670)
// still closes the double-activation race even across a network hop, not a
// client-side "check-then-create" sequence, which would reopen exactly that race.
func TestRemoteStorageBreakGlass_ConcurrentActivationRace_RealServer(t *testing.T) {
	_, downstream, projectID, baseURL, apiKey := newUpstreamDownstreamForBreakGlass(t)
	now := time.Now()

	const n = 20
	var successCount atomic.Int64
	var conflictCount atomic.Int64
	var otherErrCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			// Each racer gets its OWN RemoteStorage client (see
			// newBreakGlassRemoteClient's doc comment) so the 19 EXPECTED 409
			// Conflict responses from losing racers can't trip a shared client's
			// circuit breaker.
			client := newBreakGlassRemoteClient(t, baseURL, apiKey)
			_, err := client.Storage().CreateBreakGlassActivation(
				context.Background(), buildActiveBreakGlassActivation(now, projectID, 99))
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, coreStorage.ErrBreakGlassAlreadyActive):
				conflictCount.Add(1)
			default:
				otherErrCount.Add(1)
				t.Logf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	assert.Zero(t, otherErrCount.Load(), "every losing racer must fail with the sentinel, not some other error")
	assert.EqualValues(t, 1, successCount.Load(), "exactly one concurrent activation must win, regardless of goroutine scheduling")
	assert.EqualValues(t, n-1, conflictCount.Load())

	// And the upstream's own storage agrees: exactly one 'active' row exists for
	// this (project, user).
	rows, err := downstream.Storage().ListBreakGlassActivations(context.Background(), projectID)
	require.NoError(t, err)
	activeCount := 0
	for _, r := range rows {
		if r.UserID == 99 && r.State == core.BreakGlassActive {
			activeCount++
		}
	}
	assert.Equal(t, 1, activeCount)
}

// TestRemoteStorageBreakGlass_ConcurrentRevokeRace_RealServer proves the OTHER
// half of #519's atomicity requirement: N concurrent "revoke" requests against
// the SAME already-active activation must yield exactly one winner, via
// RevokeBreakGlassActivationProxy's conditional `UPDATE ... WHERE id = ? AND
// state = 'active'` write (local_break_glass.go's RevokeBreakGlassActivation) —
// not a client-side "GET, check state, then PUT" sequence, which would reopen a
// double-revoke TOCTOU race.
func TestRemoteStorageBreakGlass_ConcurrentRevokeRace_RealServer(t *testing.T) {
	_, downstream, projectID, baseURL, apiKey := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()

	act, err := downstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 55))
	require.NoError(t, err)

	const n = 20
	var successCount atomic.Int64
	var conflictCount atomic.Int64
	var otherErrCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(revokedBy uint) {
			defer wg.Done()
			// Each racer gets its OWN RemoteStorage client (see
			// newBreakGlassRemoteClient's doc comment) so the 19 EXPECTED 409
			// Conflict responses from losing racers can't trip a shared client's
			// circuit breaker.
			client := newBreakGlassRemoteClient(t, baseURL, apiKey)
			err := client.Storage().RevokeBreakGlassActivation(context.Background(), act.ID, revokedBy, time.Now())
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, coreStorage.ErrBreakGlassNotActive):
				conflictCount.Add(1)
			default:
				otherErrCount.Add(1)
				t.Logf("unexpected error: %v", err)
			}
		}(uint(i + 1))
	}
	wg.Wait()

	assert.Zero(t, otherErrCount.Load(), "every losing racer must fail with the sentinel, not some other error")
	assert.EqualValues(t, 1, successCount.Load(), "exactly one concurrent revoke must win, regardless of goroutine scheduling")
	assert.EqualValues(t, n-1, conflictCount.Load())

	final, err := downstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassRevoked, final.State)
}
