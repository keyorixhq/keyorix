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

// TestRemoteStorageBreakGlass_GetList_RealServer proves
// GetBreakGlassActivation/ListBreakGlassActivations: an activation seeded
// directly against the upstream's real storage (CreateBreakGlassActivationProxy/
// UpdateBreakGlassActivationProxy were deleted -- G80 liveness sweep found no
// live caller for either; see docs/g80-remediation-notes.md) is fetchable by
// ID and listed correctly via the DOWNSTREAM's RemoteStorage — storage.type:
// remote against a real router, not a protocol mock.
func TestRemoteStorageBreakGlass_GetList_RealServer(t *testing.T) {
	upstream, downstream, projectID, _, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()

	act, err := upstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 10))
	require.NoError(t, err)
	require.NotZero(t, act.ID)

	// GetBreakGlassActivation via the downstream (RemoteStorage) round-trips
	// every field correctly.
	fetched, err := downstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, act.ID, fetched.ID)
	assert.Equal(t, "editor", fetched.RoleName)
	assert.Equal(t, core.BreakGlassActive, fetched.State)
	assert.Equal(t, projectID, fetched.ProjectID)
	assert.EqualValues(t, 10, fetched.UserID)
	assert.Equal(t, act.Justification, fetched.Justification)
	require.NotNil(t, fetched.ExpiresAt)
	assert.WithinDuration(t, *act.ExpiresAt, *fetched.ExpiresAt, time.Second)

	// A second activation for a DIFFERENT user, then list both back via the
	// downstream's ListBreakGlassActivations.
	_, err = upstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 11))
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
}

// TestRemoteStorageBreakGlass_GetNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a nonexistent activation ID.
func TestRemoteStorageBreakGlass_GetNotFound_RealServer(t *testing.T) {
	_, downstream, _, _, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetBreakGlassActivation(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageBreakGlass_RevokeActuallyRemovesTheRoleGrant is the
// independent verification session's finding (2026-08-25): a prior version of
// RevokeBreakGlassActivationProxy flipped the activation's State to "revoked"
// and returned success, but never called RemoveUserRole, leaving the granted
// role fully live in user_roles — core.Authorize kept returning true for the
// "revoked" user indefinitely. TestRemoteStorageBreakGlass_RevokeThenRevoke
// AgainFails_RealServer above only ever asserted the STATUS transition, which
// is exactly why this gap went unnoticed — a passing test whose assertion
// never touched the thing that mattered. This test seeds a REAL role grant
// matching the activation (the missing piece the other test's raw-storage-only
// activation never had a matching grant to remove in the first place), then
// asserts the grant is actually gone after revoke, not just that the status
// flipped.
// G80 documented-exception re-verification sweep (2026-08-25):
// RevokeBreakGlassActivationProxy no longer trusts a wire-supplied
// revoked_by -- the revoker is always the AUTHENTICATED caller now, via
// actorID(r), which is human-only by design. `downstream`'s shared client
// authenticates as a MACHINE credential (createNodeToken), so it can no
// longer perform a revoke at all; the revoke call now goes through a real
// human's own client instead.
func TestRemoteStorageBreakGlass_RevokeActuallyRemovesTheRoleGrant(t *testing.T) {
	upstream, _, projectID, baseURL, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()
	const pw = "Qr7#Kp2$Lm5@Vn9!"
	revoker, err := upstream.CreateUser(ctx, &core.CreateUserRequest{Username: "bg-revoker-1", Email: "bg-revoker-1@example.com", Password: pw})
	require.NoError(t, err)
	grantSystemWrite(t, upstream, revoker.ID)
	revokerSess, _, err := upstream.Login(ctx, &core.LoginRequest{Username: "bg-revoker-1", Password: pw})
	require.NoError(t, err)
	asRevoker := newBreakGlassRemoteClient(t, baseURL, revokerSess.SessionToken)

	editorRole, err := upstream.Storage().GetRoleByName(ctx, "editor")
	require.NoError(t, err)

	holder, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "bg-grant-holder", Email: "bg-grant-holder@example.com", Password: "Bg9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	require.NoError(t, upstream.AssignUserRole(ctx, 0, holder.ID, editorRole.ID, coreStorage.Scope{ProjectID: projectID}))

	stillHasIt, err := upstream.Authorize(ctx, holder.ID, "secrets.write", coreStorage.Scope{ProjectID: projectID})
	require.NoError(t, err)
	require.True(t, stillHasIt, "test setup sanity check: the holder must actually have the editor grant before revoke")

	act, err := upstream.Storage().CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: projectID, UserID: holder.ID, RoleID: editorRole.ID, RoleName: "editor",
		Justification: "prod incident #43", State: core.BreakGlassActive,
		ExpiresAt: ptrTime(now.Add(4 * time.Hour)), CreatedAt: now,
	})
	require.NoError(t, err)

	require.NoError(t, asRevoker.Storage().RevokeBreakGlassActivation(ctx, act.ID, revoker.ID, 0, time.Now()))

	final, err := upstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassRevoked, final.State, "status must flip to revoked")

	stillHasIt, err = upstream.Authorize(ctx, holder.ID, "secrets.write", coreStorage.Scope{ProjectID: projectID})
	require.NoError(t, err)
	assert.False(t, stillHasIt, "the editor grant break-glass conferred must actually be gone after revoke, not just marked revoked in the activation record")
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestRemoteStorageBreakGlass_RevokeThenRevokeAgainFails_RealServer proves
// RevokeBreakGlassActivationProxy's conditional `WHERE state = 'active'` update
// (and its 409/BREAK_GLASS_NOT_ACTIVE wire-code translation) round-trips
// correctly: revoking an already-revoked activation cleanly fails with
// storage.ErrBreakGlassNotActive, the sentinel core.RevokeBreakGlass's
// errors.Is check depends on. The activation is seeded directly against the
// upstream's real storage (CreateBreakGlassActivationProxy was deleted -- G80
// liveness sweep found no live caller; see docs/g80-remediation-notes.md).
// G80 documented-exception re-verification sweep (2026-08-25): same
// correction as TestRemoteStorageBreakGlass_RevokeActuallyRemovesTheRoleGrant
// -- revoking now requires a real, human, authenticated caller.
func TestRemoteStorageBreakGlass_RevokeThenRevokeAgainFails_RealServer(t *testing.T) {
	upstream, downstream, projectID, baseURL, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()
	const pw = "Qr7#Kp2$Lm5@Vn9!"
	revoker, err := upstream.CreateUser(ctx, &core.CreateUserRequest{Username: "bg-revoker-2", Email: "bg-revoker-2@example.com", Password: pw})
	require.NoError(t, err)
	grantSystemWrite(t, upstream, revoker.ID)
	revokerSess, _, err := upstream.Login(ctx, &core.LoginRequest{Username: "bg-revoker-2", Password: pw})
	require.NoError(t, err)
	asRevoker := newBreakGlassRemoteClient(t, baseURL, revokerSess.SessionToken)

	act, err := upstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 7))
	require.NoError(t, err)

	require.NoError(t, asRevoker.Storage().RevokeBreakGlassActivation(ctx, act.ID, revoker.ID, 0, time.Now()))

	final, err := downstream.Storage().GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassRevoked, final.State)

	err = asRevoker.Storage().RevokeBreakGlassActivation(ctx, act.ID, revoker.ID, 0, time.Now())
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrBreakGlassNotActive), "got %v", err)
}

// TestRemoteStorageBreakGlass_ConcurrentRevokeRace_RealServer proves the
// #519 atomicity requirement for revoke: N concurrent "revoke" requests
// against the SAME already-active activation must yield exactly one winner,
// via RevokeBreakGlassActivationProxy's conditional `UPDATE ... WHERE id = ?
// AND state = 'active'` write (local_break_glass.go's RevokeBreakGlassActivation)
// — not a client-side "GET, check state, then PUT" sequence, which would
// reopen a double-revoke TOCTOU race. The activation is seeded directly
// against the upstream's real storage (CreateBreakGlassActivationProxy was
// deleted -- G80 liveness sweep found no live caller; see
// docs/g80-remediation-notes.md).
// G80 documented-exception re-verification sweep (2026-08-25): same
// correction as the two tests above -- revoking now requires a real, human,
// authenticated caller, so every racer authenticates as that same human
// (identity uniqueness across racers was never the point here; per-racer
// CLIENT isolation, for the circuit-breaker reason below, still is).
func TestRemoteStorageBreakGlass_ConcurrentRevokeRace_RealServer(t *testing.T) {
	upstream, downstream, projectID, baseURL, _ := newUpstreamDownstreamForBreakGlass(t)
	ctx := context.Background()
	now := time.Now()
	const pw = "Qr7#Kp2$Lm5@Vn9!"
	revoker, err := upstream.CreateUser(ctx, &core.CreateUserRequest{Username: "bg-revoker-3", Email: "bg-revoker-3@example.com", Password: pw})
	require.NoError(t, err)
	grantSystemWrite(t, upstream, revoker.ID)
	revokerSess, _, err := upstream.Login(ctx, &core.LoginRequest{Username: "bg-revoker-3", Password: pw})
	require.NoError(t, err)
	apiKey := revokerSess.SessionToken

	act, err := upstream.Storage().CreateBreakGlassActivation(ctx, buildActiveBreakGlassActivation(now, projectID, 55))
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
			err := client.Storage().RevokeBreakGlassActivation(context.Background(), act.ID, revokedBy, 0, time.Now())
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
