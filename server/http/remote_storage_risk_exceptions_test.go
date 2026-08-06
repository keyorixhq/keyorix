package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForRiskExceptions builds the standard #452/#507/#511-style
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/risk-exceptions routes,
// server/http/handlers/risk_exceptions_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage. Mirrors
// newUpstreamDownstreamForMemberships exactly.
func newUpstreamDownstreamForRiskExceptions(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
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

// buildRiskException mirrors what internal/core.CreateRiskException computes
// (after its own title/category/justification/expiry validation) before calling
// storage.CreateRiskException — a fully-built, already-validated exception row —
// WITHOUT going through CreateRiskException itself (whose validation is
// out-of-scope core POLICY, not a storage primitive, exactly the same class of
// out-of-scope prerequisite buildDynamicSecretConfig/buildInvitedMembership
// document in the sibling proxy test files).
func buildRiskException(now time.Time, createdBy uint, title, category string, expiresAt time.Time) *models.RiskException {
	return &models.RiskException{
		Title:         title,
		Category:      category,
		Reference:     "secret:db-password",
		Justification: "vendor migration in progress; MFA rollout blocked until Q3",
		CreatedBy:     createdBy,
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
	}
}

// TestRemoteStorageRiskExceptions_CreateGetListUpdate_RealServer proves the #519
// fix for CreateRiskException/GetRiskException/ListRiskExceptions/
// UpdateRiskException: an exception is genuinely persisted on the upstream
// server via the DOWNSTREAM's RemoteStorage, fetchable by ID, listed, and
// updatable (revoke/approve bookkeeping) — all via storage.type: remote against
// a real router, not a protocol mock.
func TestRemoteStorageRiskExceptions_CreateGetListUpdate_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)

	exc, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "MFA rollout delay", "mfa", expiresAt))
	require.NoError(t, err, "creating a risk exception must succeed via storage.type: remote")
	require.NotZero(t, exc.ID, "the upstream must assign a real ID")
	assert.Equal(t, "MFA rollout delay", exc.Title)
	assert.Equal(t, "mfa", exc.Category)
	assert.False(t, exc.Revoked)
	assert.False(t, exc.Approved)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.Equal(t, "MFA rollout delay", direct.Title)

	// GetRiskException via the downstream (RemoteStorage) round-trips every field
	// correctly.
	fetched, err := downstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.Equal(t, exc.ID, fetched.ID)
	assert.Equal(t, exc.Title, fetched.Title)
	assert.Equal(t, exc.Category, fetched.Category)
	assert.Equal(t, exc.Reference, fetched.Reference)
	assert.Equal(t, exc.Justification, fetched.Justification)
	assert.WithinDuration(t, exc.ExpiresAt, fetched.ExpiresAt, time.Second)

	// A second exception, then list both back via the downstream's
	// ListRiskExceptions(activeOnly=false).
	_, err = downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "Dormant service account", "dormant_access", expiresAt))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListRiskExceptions(ctx, false)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	titles := map[string]bool{}
	for _, r := range rows {
		titles[r.Title] = true
	}
	assert.True(t, titles["MFA rollout delay"])
	assert.True(t, titles["Dormant service account"])

	// UpdateRiskException: approve the first exception (dual control — a
	// DIFFERENT actor than the creator) via the downstream, confirm the
	// transition is visible directly on the upstream.
	approvedAt := time.Now()
	fetched.Approved = true
	fetched.ApprovedBy = 2
	fetched.ApprovedAt = &approvedAt
	require.NoError(t, downstream.Storage().UpdateRiskException(ctx, fetched))

	reFetched, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.True(t, reFetched.Approved, "the approval must be visible directly on the upstream's own storage")
	assert.Equal(t, uint(2), reFetched.ApprovedBy)
	require.NotNil(t, reFetched.ApprovedAt)
}

// TestRemoteStorageRiskExceptions_GetNotFound_RealServer proves a clean
// not-found error (not a panic, not a garbage 500) for a nonexistent exception ID.
func TestRemoteStorageRiskExceptions_GetNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetRiskException(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageRiskExceptions_ActiveOnlyExcludesRevoked_RealServer proves
// ListRiskExceptions(activeOnly=true) excludes revoked rows at the storage
// layer, matching local_risk_exceptions.go's contract exactly (expiry itself is
// computed by the calling server's own core, not at the storage layer, so an
// expired-but-not-revoked row is still returned here — core is what drops it
// from an "active" view).
func TestRemoteStorageRiskExceptions_ActiveOnlyExcludesRevoked_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)

	kept, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "Kept exception", "other", expiresAt))
	require.NoError(t, err)
	revoked, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "Revoked exception", "other", expiresAt))
	require.NoError(t, err)

	revokedAt := time.Now()
	revoked.Revoked = true
	revoked.RevokedBy = 1
	revoked.RevokedAt = &revokedAt
	require.NoError(t, downstream.Storage().UpdateRiskException(ctx, revoked))

	rows, err := downstream.Storage().ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	require.Len(t, rows, 1, "active_only=true must exclude the revoked row")
	assert.Equal(t, kept.ID, rows[0].ID)

	// Directly against the upstream's own storage too, proving this isn't an
	// artifact of RemoteStorage's response cache.
	directRows, err := upstream.Storage().ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	require.Len(t, directRows, 1)
	assert.Equal(t, kept.ID, directRows[0].ID)
}

// TestRemoteStorageRiskExceptions_RevokeIfNotRevoked_ConditionalRace_RealServer
// proves the StateTransitionMissingCAS.ql fix end-to-end, over a real HTTP hop
// through the downstream's RemoteStorage against the upstream's REAL router —
// not a protocol mock: two callers racing RevokeRiskExceptionIfNotRevoked for
// the SAME exception (mirroring internal/core.RevokeRiskException's own
// read-then-write) must not both "win". The first conditional write must
// match (matched=true) and persist its attribution; the second, racing against
// a row the first already moved to revoked=true, must be rejected
// (matched=false) rather than silently re-applied over the winner.
func TestRemoteStorageRiskExceptions_RevokeIfNotRevoked_ConditionalRace_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)

	exc, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "Racing revoke", "other", expiresAt))
	require.NoError(t, err)

	// Two admins independently read the still-unrevoked row (the TOCTOU window
	// internal/core.RevokeRiskException's own GetRiskException-then-write
	// sequence has), each preparing their own conditional revoke write.
	firstRead, err := downstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	firstRevokedAt := time.Now()
	firstRead.Revoked = true
	firstRead.RevokedBy = 1
	firstRead.RevokedAt = &firstRevokedAt

	secondRead, err := downstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	secondRevokedAt := time.Now()
	secondRead.Revoked = true
	secondRead.RevokedBy = 2
	secondRead.RevokedAt = &secondRevokedAt

	// First admin's conditional revoke lands and wins.
	matched, err := downstream.Storage().RevokeRiskExceptionIfNotRevoked(ctx, firstRead)
	require.NoError(t, err)
	assert.True(t, matched, "the first writer must win")

	// Second admin's conditional revoke, racing against a row the first write
	// already moved to revoked=true, must be rejected — not silently
	// re-applied (re-attributing the revoke away from admin 1 to admin 2, the
	// exact clobber this fix closes).
	matched, err = downstream.Storage().RevokeRiskExceptionIfNotRevoked(ctx, secondRead)
	require.NoError(t, err)
	assert.False(t, matched, "the second writer must lose, not clobber the first revoke")

	// The upstream's own persisted row must reflect the FIRST admin's
	// attribution, proving the second write never landed.
	final, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.True(t, final.Revoked)
	assert.Equal(t, uint(1), final.RevokedBy, "the winning first admin's attribution must be the persisted state")
}

// TestRemoteStorageRiskExceptions_ApproveIfPending_ConditionalRace_RealServer
// is the approve analogue, end-to-end over real HTTP: a revoke and an approve
// racing the SAME exception must not both land — an exception left in a
// "revoked AND approved" state would defeat dual control's whole purpose (an
// approved exception suppresses its matched violation from the compliance
// posture, so a revoked-then-approved exception would wrongly keep suppressing
// it).
func TestRemoteStorageRiskExceptions_ApproveIfPending_ConditionalRace_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)

	exc, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 9, "Racing revoke vs approve", "other", expiresAt))
	require.NoError(t, err)

	// The revoker and the (different, dual-control-compliant) approver both
	// read the same still-pending row before either write lands.
	revokeRead, err := downstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	revokedAt := time.Now()
	revokeRead.Revoked = true
	revokeRead.RevokedBy = 1
	revokeRead.RevokedAt = &revokedAt

	approveRead, err := downstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	approvedAt := time.Now()
	approveRead.Approved = true
	approveRead.ApprovedBy = 2
	approveRead.ApprovedAt = &approvedAt

	// Revoke lands first.
	matched, err := downstream.Storage().RevokeRiskExceptionIfNotRevoked(ctx, revokeRead)
	require.NoError(t, err)
	assert.True(t, matched)

	// The approve, racing against a row that is no longer unrevoked, must be
	// rejected.
	matched, err = downstream.Storage().ApproveRiskExceptionIfPending(ctx, approveRead)
	require.NoError(t, err)
	assert.False(t, matched, "an approve racing a revoke must lose, not mark a revoked exception approved")

	final, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.True(t, final.Revoked)
	assert.False(t, final.Approved, "the revoked exception must never end up approved")
}
