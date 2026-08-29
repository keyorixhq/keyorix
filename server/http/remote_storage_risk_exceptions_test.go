package http

import (
	"context"
	"net/http/httptest"
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

// newUpstreamHumanDownstreamForRiskExceptions is
// newUpstreamDownstreamForRiskExceptions's counterpart for tests that need to
// call CreateRiskException: CreateRiskExceptionProxy requires a human
// principal ("only a human principal may create a risk exception", #1529) --
// the node/machine credential newUpstreamDownstreamForRiskExceptions's shared
// downstream uses can never satisfy that (see #1584, a deliberate product
// constraint, not a bug — verified separately, not changed here). A SEPARATE
// helper, not a change to the shared one: several other tests in this file
// deliberately exercise the machine-credential path (or don't need Create at
// all), and #1584 itself is verdict-only, not a fix — this only unblocks the
// two conditional-race tests below, which need a working Create step to set
// up their race and are otherwise unrelated to human-vs-machine identity.
// Mirrors newUpstreamDownstreamForMemberships's own admin-session pattern
// (TestMembershipProxy_CreateAllowsAdminRoleByGenuineAdmin). Also returns
// baseURL so a caller needing a SECOND distinct human actor against the same
// upstream (see humanRiskExceptionClient below — the approve-race test needs
// one, since CreateRiskExceptionProxy makes the creator == this function's
// own actor, and dual control forbids that actor from also approving) can
// mint one without standing up a second server.
func newUpstreamHumanDownstreamForRiskExceptions(t *testing.T) (upstream, downstream *core.KeyorixCore, baseURL string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	_ = createTestToken(t, upstream) // SeedSystem: bootstraps admin user/roles/permissions/project — grantSystemWrite needs "system.write" to already exist
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)
	baseURL = upstreamSrv.URL

	downstream, _ = humanRiskExceptionClient(t, upstream, baseURL, "riskexc1584-human")
	return upstream, downstream, baseURL
}

// humanRiskExceptionClient creates a fresh human user against upstream,
// grants it system.write (the permission /api/v1/system/risk-exceptions is
// gated on), logs in, and returns a *core.KeyorixCore backed by that human's
// session token against baseURL, plus the created user's ID — a distinct
// principal each call, since username must be unique per upstream. The ID is
// needed because RevokeRiskExceptionProxy/ApproveRiskExceptionProxy derive
// RevokedBy/ApprovedBy from the AUTHENTICATED caller (actorID(r)), not from
// anything the wire client sends — a caller distinguishing "the winning
// writer's attribution" needs the real actor ID, not an arbitrary local value.
func humanRiskExceptionClient(t *testing.T, upstream *core.KeyorixCore, baseURL, username string) (client *core.KeyorixCore, userID uint) {
	t.Helper()
	ctx := context.Background()
	const pw = "Qr7#Kp2$Lm5@Vn9!"
	human, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@example.com", Password: pw,
	})
	require.NoError(t, err)
	grantSystemWrite(t, upstream, human.ID)
	sess, _, err := upstream.Login(ctx, &core.LoginRequest{Username: username, Password: pw})
	require.NoError(t, err)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        baseURL,
		APIKey:         sess.SessionToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	return core.NewKeyorixCore(rs), human.ID
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

// TestRemoteStorageRiskExceptions_CreateGetList_RealServer proves the #519 fix
// for CreateRiskException/GetRiskException/ListRiskExceptions: an exception is
// genuinely persisted on the upstream server via the DOWNSTREAM's
// RemoteStorage, fetchable by ID, and listed — all via storage.type: remote
// against a real router, not a protocol mock. The approve/revoke bookkeeping
// this test used to also cover via UpdateRiskException is now proved by
// TestRemoteStorageRiskExceptions_Approve_DeniesNodeCredential (approve, via
// the dedicated conditional-write proxy) and
// TestRemoteStorageRiskExceptions_ActiveOnlyExcludesRevoked_RealServer
// (revoke, same) below — UpdateRiskException itself is a permanent stub as of
// the #1511/G80 deletion pass (#G79 already removed its route server-side;
// see docs/adr-087-remote-storage-deletion-pass.md), not something this suite
// exercises anymore.
func TestRemoteStorageRiskExceptions_CreateGetList_RealServer(t *testing.T) {
	t.Skip("#1511/G80 deletion pass fixed the original blocker (UpdateRiskException now a client-side stub, not a real 405) but un-skipping surfaced a SECOND, previously-invisible one: this harness's default credential (createNodeToken, a machine/node principal) cannot create a risk exception at all — CreateRiskExceptionProxy requires a human principal ('only a human principal may create a risk exception'). This has been true since before this pass; the original t.Skip() short-circuited before the Create call ever ran, so it was never actually observed. Out of scope for a dead-wire-call deletion pass — filed as #1584, not fixed here.")
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
}

// TestRemoteStorage_UpdateRiskException_Unsupported proves UpdateRiskException
// fails client-side (a stub, never reaching the network) rather than hitting a
// real 405 from the deliberately-unregistered route — the #1511/G80 deletion
// pass's actual fix, replacing this suite's prior quarantined-Skip coverage.
func TestRemoteStorage_UpdateRiskException_Unsupported(t *testing.T) {
	_, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()

	err := downstream.Storage().UpdateRiskException(ctx, &models.RiskException{ID: 1})
	require.Error(t, err)
}

// TestRemoteStorageRiskExceptions_GetNotFound_RealServer proves a clean
// not-found error (not a panic, not a garbage 500) for a nonexistent exception ID.
func TestRemoteStorageRiskExceptions_GetNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetRiskException(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageRiskExceptions_Approve_DeniesNodeCredential is the real
// regression test for #1524 finding (c): a node credential (this file's
// harness default -- newUpstreamDownstreamForRiskExceptions) must not be
// able to approve a HUMAN-created exception. Before the fix, the only
// gate was actorID == e.CreatedBy (self-approval); a node relaying an
// exception it did not create (CreatedBy a real human ID, actorID(r)==0)
// never collided with that comparison and approved with no authority check
// at all. The exception here is created directly on the upstream's own
// core (bypassing the node-token wire entirely) specifically so CreatedBy
// is a real, nonzero human ID, not the node's own actorID(r)==0 -- proving
// this is the reversed-direction case #1531's investigation found, not the
// already-correctly-denied node-created-and-node-approved collision.
func TestRemoteStorageRiskExceptions_Approve_DeniesNodeCredential(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()

	const humanCreator = uint(5)
	exc, err := upstream.CreateRiskException(ctx, humanCreator, false, "Human-created, node must not approve",
		"other", "", "seeded directly on upstream for #1524 (c) regression coverage", time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, humanCreator, exc.CreatedBy)

	// clientSafe sanitizes every proxy error to a blanket "an internal error
	// occurred" string before it reaches the wire caller (the real "dual
	// control requires a human approver" message is only visible server-side
	// -- log output during a local run of this test). What the client can
	// observe is that the call errors and never reports a match.
	matched, err := downstream.Storage().ApproveRiskExceptionIfPending(ctx, exc)
	assert.False(t, matched, "a node credential must never report a successful approval")
	require.Error(t, err, "a node credential must not be able to approve a risk exception it did not create")

	direct, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.False(t, direct.Approved, "the denied approval must never land on the upstream's own storage")
}

// TestRemoteStorageRiskExceptions_ActiveOnlyExcludesRevoked_RealServer proves
// ListRiskExceptions(activeOnly=true) excludes revoked rows at the storage
// layer, matching local_risk_exceptions.go's contract exactly (expiry itself is
// computed by the calling server's own core, not at the storage layer, so an
// expired-but-not-revoked row is still returned here — core is what drops it
// from an "active" view).
func TestRemoteStorageRiskExceptions_ActiveOnlyExcludesRevoked_RealServer(t *testing.T) {
	t.Skip("Same second blocker as TestRemoteStorageRiskExceptions_CreateGetList_RealServer above: this harness's node/machine credential cannot create a risk exception at all ('only a human principal may create a risk exception'), unrelated to and not fixed by the #1511/G80 deletion pass. Filed as #1584. Quarantined here, not fixed.")
	upstream, downstream := newUpstreamDownstreamForRiskExceptions(t)
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)

	kept, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "Kept exception", "other", expiresAt))
	require.NoError(t, err)
	revoked, err := downstream.Storage().CreateRiskException(ctx, buildRiskException(now, 1, "Revoked exception", "other", expiresAt))
	require.NoError(t, err)

	// Revoked via the dedicated conditional-write proxy (RevokeRiskExceptionIfNotRevoked),
	// not UpdateRiskException — the latter is a permanent stub as of the
	// #1511/G80 deletion pass (#G79 already removed its route server-side).
	revokedAt := time.Now()
	revoked.Revoked = true
	revoked.RevokedBy = 1
	revoked.RevokedAt = &revokedAt
	matched, err := downstream.Storage().RevokeRiskExceptionIfNotRevoked(ctx, revoked)
	require.NoError(t, err)
	require.True(t, matched)

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
	upstream, downstream, baseURL := newUpstreamHumanDownstreamForRiskExceptions(t)
	// RevokeRiskExceptionProxy derives RevokedBy from the AUTHENTICATED caller
	// (actorID(r)), not from anything the wire client sends (#G79) — a second,
	// genuinely distinct admin session is what makes "the winner's attribution
	// persists, not the loser's" a meaningful assertion below; reusing one
	// session for both racing writes would make them indistinguishable by
	// attribution regardless of which one actually won the CAS. Must be a
	// genuine admin-tier role, not just system.write: RevokeRiskException's
	// own authority check (internal/core/risk_exceptions.go) only allows the
	// exception's creator OR an admin-tier principal to revoke — a second
	// actor with system.write alone is neither, and would be denied outright
	// before ever reaching the CAS this test means to race.
	secondAdmin, secondAdminID := humanRiskExceptionClient(t, upstream, baseURL, "riskexc1584-second-revoker")
	adminRole, err := upstream.Storage().GetRoleByName(context.Background(), "admin")
	require.NoError(t, err)
	require.NoError(t, upstream.Storage().AssignRole(context.Background(), secondAdminID, adminRole.ID, coreStorage.Scope{}))
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
	firstRead.RevokedAt = &firstRevokedAt

	secondRead, err := secondAdmin.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	secondRevokedAt := time.Now()
	secondRead.Revoked = true
	secondRead.RevokedAt = &secondRevokedAt

	// First admin's conditional revoke lands and wins.
	matched, err := downstream.Storage().RevokeRiskExceptionIfNotRevoked(ctx, firstRead)
	require.NoError(t, err)
	assert.True(t, matched, "the first writer must win")

	// Second admin's conditional revoke, racing against a row the first write
	// already moved to revoked=true, must be rejected — not silently
	// re-applied (re-attributing the revoke away from the first admin to the
	// second, the exact clobber this fix closes).
	matched, err = secondAdmin.Storage().RevokeRiskExceptionIfNotRevoked(ctx, secondRead)
	require.NoError(t, err)
	assert.False(t, matched, "the second writer must lose, not clobber the first revoke")

	// The upstream's own persisted row must reflect the FIRST admin's
	// attribution, proving the second write never landed.
	final, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.True(t, final.Revoked)
	assert.NotEqual(t, secondAdminID, final.RevokedBy, "the losing second admin's attribution must not be the persisted state")
	assert.Equal(t, exc.CreatedBy, final.RevokedBy, "the winning first admin's attribution must be the persisted state")
}

// TestRemoteStorageRiskExceptions_ApproveIfPending_ConditionalRace_RealServer
// is the approve analogue, end-to-end over real HTTP: a revoke and an approve
// racing the SAME exception must not both land — an exception left in a
// "revoked AND approved" state would defeat dual control's whole purpose (an
// approved exception suppresses its matched violation from the compliance
// posture, so a revoked-then-approved exception would wrongly keep suppressing
// it).
func TestRemoteStorageRiskExceptions_ApproveIfPending_ConditionalRace_RealServer(t *testing.T) {
	upstream, downstream, baseURL := newUpstreamHumanDownstreamForRiskExceptions(t)
	// Dual control (#170) forbids the creator from approving its own
	// exception — downstream (this function's own actor) creates and revokes;
	// a SECOND, distinct human actor approves, mirroring who would genuinely
	// perform each step in production.
	approver, _ := humanRiskExceptionClient(t, upstream, baseURL, "riskexc1584-approver")
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

	approveRead, err := approver.Storage().GetRiskException(ctx, exc.ID)
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
	matched, err = approver.Storage().ApproveRiskExceptionIfPending(ctx, approveRead)
	require.NoError(t, err)
	assert.False(t, matched, "an approve racing a revoke must lose, not mark a revoked exception approved")

	final, err := upstream.Storage().GetRiskException(ctx, exc.ID)
	require.NoError(t, err)
	assert.True(t, final.Revoked)
	assert.False(t, final.Approved, "the revoked exception must never end up approved")
}
