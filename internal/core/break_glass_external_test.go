package core_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enableBreakGlass(h *testhelper.RBACTestHelper, role string, def, max time.Duration) {
	h.CoreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: role, DefaultTTL: def, MaxTTL: max,
	})
}

func migrateBreakGlass(t *testing.T, h *testhelper.RBACTestHelper) {
	require.NoError(t, h.DB.AutoMigrate(&models.BreakGlassActivation{}, &models.AuditEvent{}))
	// Mirrors ensureBreakGlassActiveIndex (internal/storage/factory.go) — this is
	// the real production constraint ActivateBreakGlass's "already active" path
	// depends on; without it here, these tests exercise a materially weaker
	// invariant than production actually enforces (internal/storage/store/
	// local_break_glass_test.go's newBreakGlassStore creates the same index for
	// the same reason).
	require.NoError(t, h.DB.Exec(
		"CREATE UNIQUE INDEX uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
	).Error)
}

// makeProjectMember gives the user a baseline (viewer) role at the project so they
// satisfy break-glass's project-eligibility gate — the realistic scenario is a member
// who lacks the specific emergency power, not an unaffiliated outsider.
func makeProjectMember(t *testing.T, h *testhelper.RBACTestHelper, userID, projectID uint) {
	pid := projectID
	h.AssignUserRole(t, userID, 4, &pid) // role 4 = viewer
}

// Activating break-glass time-bound-grants the configured emergency role to the
// caller and records the justified activation.
func TestActivateBreakGlass_GrantsTimeBoundRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour) // role 3

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident #42", "")
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassActive, act.State)
	assert.Equal(t, uint(3), act.RoleID)
	require.NotNil(t, act.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(4*time.Hour), *act.ExpiresAt, 2*time.Minute)

	// alice now holds the emergency (editor) role at the project, time-bound.
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.Contains(t, ids, uint(3), "emergency role is active")

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "prod incident #42", list[0].Justification)
}

// A requested TTL is capped at the configured maximum.
func TestActivateBreakGlass_CapsTTL(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 1*time.Hour) // max 1h

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, 2)
	act, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "prod incident", "10h")
	require.NoError(t, err)
	require.NotNil(t, act.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(1*time.Hour), *act.ExpiresAt, 2*time.Minute, "10h request capped at the 1h max")
}

// With no MaxTTL configured, a requested TTL is still bounded — to the default TTL,
// not honored unbounded. The core enforces "break-glass is time-bound" itself rather
// than relying on the config layer to have supplied a ceiling.
func TestActivateBreakGlass_UnsetMaxTTLFloorsToDefault(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 0) // MaxTTL unset (0)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, 2)
	act, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "prod incident", "720h") // 30-day override
	require.NoError(t, err)
	require.NotNil(t, act.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(4*time.Hour), *act.ExpiresAt, 2*time.Minute,
		"with no MaxTTL, an override must be bounded to the default TTL, not honored as 720h")
}

// Break-glass refuses when disabled, and a justification is mandatory.
func TestActivateBreakGlass_DisabledAndJustificationRequired(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)

	// Disabled (default policy) → refused.
	_, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "prod incident", "")
	require.Error(t, err)

	// Enabled but no justification → refused.
	enableBreakGlass(h, "editor", time.Hour, time.Hour)
	_, err = h.CoreService.ActivateBreakGlass(ctx, 2, 10, "", "")
	require.Error(t, err)
}

// #413: the justification becomes a PERMANENT audit-trail record of why a real
// security incident required emergency access. A bare non-empty check lets a
// single whitespace character (or any string under a reasonable minimum length)
// satisfy it, producing a useless audit record. Whitespace-only and too-short
// justifications must be refused; a genuine one, including one with leading/
// trailing whitespace that trims down to a valid length, must be accepted.
func TestActivateBreakGlass_RejectsWhitespaceOnlyAndTooShortJustification(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", time.Hour, time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	// A single space (or any whitespace-only string) must not satisfy the check.
	_, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, " ", "")
	require.Error(t, err, "a whitespace-only justification must be refused")
	assert.Contains(t, err.Error(), "justification")

	// Too short even after trimming (below the minimum length) must be refused.
	_, err = h.CoreService.ActivateBreakGlass(ctx, proj, 10, "  bad  ", "")
	require.Error(t, err, "a too-short justification must be refused even with padding whitespace")
	assert.Contains(t, err.Error(), "justification")

	// No activation was recorded for either rejected attempt.
	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, list)

	// A genuine justification — including one with surrounding whitespace that
	// trims down to a valid length — is accepted, and the stored value is trimmed.
	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "  prod database incident  ", "")
	require.NoError(t, err, "a genuine justification must be accepted")
	assert.Equal(t, "prod database incident", act.Justification, "the stored justification must be trimmed")
}

// Revoking an activation removes the grant early and marks it revoked.
func TestRevokeBreakGlass_RemovesGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	require.NoError(t, h.CoreService.RevokeBreakGlass(ctx, 1, 0, proj, act.ID))

	// The emergency role is gone.
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.NotContains(t, ids, uint(3))

	// The record is revoked, and re-revoking fails.
	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, core.BreakGlassRevoked, list[0].State)
	require.Error(t, h.CoreService.RevokeBreakGlass(ctx, 1, 0, proj, act.ID))
}

// #1653 reopened: a caller must never be refused a revoke because of what a
// wall-clock-derived State reads. This activation's persisted state has
// already been reconciled to 'expired' (simulating ReconcileExpiredBreakGlassActivation
// having run, e.g. because the same user re-activated after this grant's TTL
// lapsed) -- revoking a DIFFERENT, still-un-revoked activation by its own ID
// must still succeed, exercising the exact guard (RevokeBreakGlass's
// `activation.State == BreakGlassRevoked` check) and the exact storage-layer
// conditional UPDATE (`state IN ('active','expired')`) this finding fixed.
func TestRevokeBreakGlass_NotBlockedByExpiredState(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	// Simulate the reconciliation that happens on a genuine TTL lapse -- the
	// row's PERSISTED state, not just a read-time projection.
	require.NoError(t, h.DB.Model(&models.BreakGlassActivation{}).
		Where("id = ?", act.ID).
		Update("state", core.BreakGlassExpired).Error)

	err = h.CoreService.RevokeBreakGlass(ctx, 1, 0, proj, act.ID)
	require.NoError(t, err, "revoking a TTL-lapsed (State == expired) activation must succeed, not be refused as 'not active'")

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, core.BreakGlassRevoked, list[0].State, "the activation must end up genuinely revoked, not left expired")
}

// #1573: a machine identity holding project-scoped roles.assign can revoke a
// break-glass activation. actorID (0, ADR-030) alone loses which machine did
// it; RevokedByMachineIdentityID must carry it through to the persisted row.
func TestRevokeBreakGlass_RecordsActingMachineIdentity(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	require.NoError(t, h.CoreService.RevokeBreakGlass(ctx, 0, 42, proj, act.ID))

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Zero(t, list[0].RevokedBy)
	assert.Equal(t, uint(42), list[0].RevokedByMachineIdentityID)
}

// #304: the storage-layer state transition is a single conditional UPDATE
// (WHERE state = active), not a read-modify-write. Revoking the same activation
// twice in a row must let only the first call actually transition state — the
// second must fail cleanly with storage.ErrBreakGlassNotActive, and the first
// revoker's attribution (RevokedBy/RevokedAt) must survive untouched rather than
// being silently overwritten by the second attempt.
func TestRevokeBreakGlassActivation_ConditionalUpdateOnlyFirstAttemptWins(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	firstRevokeAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	require.NoError(t, h.Storage.RevokeBreakGlassActivation(ctx, act.ID, 100, 0, firstRevokeAt))

	secondRevokeAt := time.Now().UTC().Truncate(time.Second)
	err = h.Storage.RevokeBreakGlassActivation(ctx, act.ID, 200, 0, secondRevokeAt)
	require.Error(t, err, "a second conditional revoke of an already-revoked activation must fail")
	assert.ErrorIs(t, err, storage.ErrBreakGlassNotActive)

	got, err := h.Storage.GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassRevoked, got.State)
	assert.Equal(t, uint(100), got.RevokedBy, "the first revoker's attribution must survive a racing second attempt")
	require.NotNil(t, got.RevokedAt)
	assert.WithinDuration(t, firstRevokeAt, *got.RevokedAt, time.Second)
}

// #304 end to end: two admins racing to revoke the same activation concurrently
// must not both succeed and must not corrupt RevokedBy/RevokedAt attribution —
// exactly one RevokeBreakGlass call wins, the other gets a clean "not active" error.
func TestRevokeBreakGlass_ConcurrentRevokesOnlyOneWins(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)
	// A single shared connection so both goroutines' conditional UPDATEs interleave
	// through the same in-memory SQLite database rather than each opening its own
	// independent (and differently-seeded) :memory: connection.
	h.SqlDB.SetMaxOpenConns(1)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	admins := []uint{100, 200}
	errs := make([]error, len(admins))
	var wg sync.WaitGroup
	for i, admin := range admins {
		wg.Add(1)
		go func(i int, admin uint) {
			defer wg.Done()
			errs[i] = h.CoreService.RevokeBreakGlass(ctx, admin, 0, proj, act.ID)
		}(i, admin)
	}
	wg.Wait()

	successCount := 0
	var winner uint
	for i, e := range errs {
		if e == nil {
			successCount++
			winner = admins[i]
		}
	}
	assert.Equal(t, 1, successCount, "exactly one concurrent revoke must win")

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, core.BreakGlassRevoked, list[0].State)
	assert.Equal(t, winner, list[0].RevokedBy, "attribution must belong to whichever admin's conditional update actually won")
}

// List reports an active record past its expiry as expired -- a read-time
// projection, never persisted.
//
// #1653 reopened (2026-09-02): this test originally asserted the OPPOSITE --
// that the transition WAS persisted (#G43) -- reasoning that any consumer
// reading the table directly would otherwise see a stale 'active' state.
// That reasoning missed that persisting from THIS read path was itself the
// defect: RevokeBreakGlass's guard (and its remote-storage-proxy mirror) read
// State to decide whether to attempt the real de-authorization action, so a
// wall-clock hiccup in the old persisting write could silently block a
// legitimate emergency revoke. The fix moved persistence to
// ReconcileExpiredBreakGlassActivation, called only from ActivateBreakGlass
// (a mutating operation) -- this function, and the storage layer beneath it,
// must now NEVER write from a read.
func TestListBreakGlassActivations_ExpiredReconciliation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)

	const proj = uint(2)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	require.NoError(t, h.DB.Create(&models.BreakGlassActivation{
		ProjectID: proj, UserID: 10, RoleID: 3, RoleName: "editor",
		Justification: "old", State: core.BreakGlassActive, ExpiresAt: &past, CreatedAt: past,
	}).Error)

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, core.BreakGlassExpired, list[0].State, "an active grant past expiry reads as expired")

	// The persisted row must be UNCHANGED -- still 'active' -- proving this
	// read never wrote anything. This is the durable invariant #1653's fix
	// establishes: State is never persisted from a read path.
	var stored models.BreakGlassActivation
	require.NoError(t, h.DB.First(&stored, list[0].ID).Error)
	assert.Equal(t, core.BreakGlassActive, stored.State, "a list (read) must never persist the TTL-lapse transition to the database row")
}

// An expired break-glass grant must confer NO access at the authorization boundary — not
// merely show as "expired" in the activation list. Break-glass self-grants a time-bound
// emergency role; once it lapses, Authorize must deny, relying on the expires_at filter in
// role resolution (GetUserRoleIDsAt). This drives the real activate → authorize → expire
// flow end to end, rather than only the SQL filter in isolation.
func TestBreakGlass_ExpiredGrantDeniesAuthorization(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour) // editor = role 3 (secrets.read + secrets.write)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	_, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	// While active, the emergency role authorizes a write at the project scope.
	ok, err := h.CoreService.Authorize(ctx, 10, "secrets.write", core.Scope{ProjectID: proj})
	require.NoError(t, err)
	require.True(t, ok, "break-glass must grant the emergency permission while active")

	// Simulate the grant lapsing: push its expiry into the past (equivalent to the TTL
	// elapsing). Role resolution filters out expires_at <= now, so the role drops away.
	require.NoError(t, h.DB.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ?", 10, 3).
		Update("expires_at", time.Now().UTC().Add(-time.Hour)).Error)

	// The emergency role no longer resolves...
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.NotContains(t, ids, uint(3), "an expired emergency role must drop out of role resolution")

	// ...and Authorize denies the permission it used to grant.
	ok, err = h.CoreService.Authorize(ctx, 10, "secrets.write", core.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.False(t, ok, "an expired break-glass grant must confer no access at the authorization boundary")
}

// A user with no affiliation to the project cannot break-glass it — otherwise any
// authenticated user could self-grant the emergency role on an arbitrary project.
func TestActivateBreakGlass_RejectsNonMember(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	ctx := context.Background()
	h.CreateTestUser(t, "outsider", 10) // created, but NOT a member of project 2

	_, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "prod incident", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "members of the project")

	// And no activation was recorded for the rejected attempt.
	list, err := h.CoreService.ListBreakGlassActivations(ctx, 2)
	require.NoError(t, err)
	assert.Empty(t, list)
}

// A second activation is refused while the user already holds an active, unexpired
// grant — so a time-bound emergency grant can't be silently renewed into permanence.
func TestActivateBreakGlass_RejectsConcurrentReactivation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	_, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "first incident", "")
	require.NoError(t, err)

	// Second activation while the first is still active → refused.
	_, err = h.CoreService.ActivateBreakGlass(ctx, proj, 10, "still ongoing", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already have an active break-glass grant")

	// Exactly one activation exists.
	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)

	// Once the first is revoked, a fresh activation is allowed again.
	require.NoError(t, h.CoreService.RevokeBreakGlass(ctx, 1, 0, proj, list[0].ID))
	_, err = h.CoreService.ActivateBreakGlass(ctx, proj, 10, "new incident", "")
	require.NoError(t, err)
}

// #263: a second, real-incident break-glass activation for the same user/role/project
// must succeed once the FIRST activation's grant has naturally EXPIRED — not fail with
// "already assigned" against a stale, un-reaped user_roles row. The existing
// revoke-then-reactivate coverage above (TestActivateBreakGlass_RejectsConcurrentReactivation)
// doesn't exercise this: an explicit revoke deletes the row outright, but a natural
// expiry leaves it in place with expires_at in the past, which the assignment's
// existence check must treat as absent.
func TestActivateBreakGlass_ReactivatesAfterNaturalExpiry(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour) // editor = role 3

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	first, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "first incident", "")
	require.NoError(t, err)

	// Simulate the first grant's TTL naturally elapsing: push both the underlying
	// user_roles row's expiry AND the activation record's expiry into the past — the
	// same effect a real elapsed TTL has, without waiting hours in the test. Critically,
	// unlike RevokeBreakGlass, this does NOT delete the user_roles row.
	// .UTC() matters here (G81/#1653): this raw .Update() bypasses
	// BreakGlassActivation's BeforeSave hook's normal UTC normalization (a
	// single-column GORM Update does not re-derive its bound value from a
	// hook-mutated struct field), so a naive local-time value here would not
	// match ReconcileExpiredBreakGlassActivation's UTC-bound SQL comparison —
	// not a real gap, since CreateBreakGlassActivation (the only real write
	// path) always normalizes via BeforeSave; only this test's own shortcut
	// for simulating elapsed time needs to mirror that normalization by hand.
	past := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, h.DB.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ?", 10, 3).
		Update("expires_at", past).Error)
	require.NoError(t, h.DB.Model(&models.BreakGlassActivation{}).
		Where("id = ?", first.ID).
		Update("expires_at", past).Error)

	// A second, real-incident activation for the same user/role/project must now
	// succeed — the first grant is expired, not live.
	second, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "second incident", "")
	require.NoError(t, err, "reactivation after natural expiry must succeed, not fail with 'already assigned'")
	assert.Equal(t, core.BreakGlassActive, second.State)

	// The fresh grant is live and authorizing.
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.Contains(t, ids, uint(3), "the fresh reactivation grant is live")
}

// A user affiliated with the project ONLY via a global/install-wide role (e.g. the
// system_viewer baseline every SSO user receives) is NOT a project member and must be
// refused — otherwise any authenticated user could break-glass any project.
func TestActivateBreakGlass_RejectsGlobalOnlyAffiliation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	ctx := context.Background()
	h.CreateTestUser(t, "ssouser", 10)
	h.AssignUserRole(t, 10, 4, nil) // viewer at GLOBAL scope (project_id = 0), not project-scoped

	_, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "prod incident", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "members of the project")
}

// The emergency role must not carry roles.assign: a time-bound role that can assign
// roles (or issue credentials) could be used during the window to mint a PERMANENT
// grant that outlives break-glass, defeating auto-expiry. A (non-admin) role carrying
// roles.assign is refused; a contained role (editor — no roles.assign) is fine.
func TestActivateBreakGlass_RejectsRoleAssignEmergencyRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	// A delegated, NON-admin role that nonetheless carries roles.assign (perm id 13).
	// name_folded is NOT NULL (#1642); already pure-lowercase ASCII.
	h.ExecuteRawSQL(t, "INSERT OR IGNORE INTO roles (id, name, name_folded, description) VALUES (?, ?, ?, ?)",
		50, "delegated_approver", "delegated_approver", "non-admin role that can assign roles")
	h.ExecuteRawSQL(t, "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", 50, 13)

	enableBreakGlass(h, "delegated_approver", 4*time.Hour, 24*time.Hour)
	_, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assign roles")

	// editor is contained (no roles.assign) → allowed.
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)
	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassActive, act.State)
}

// An install-wide admin role (super_admin/admin/system_admin) must not be usable as the
// emergency role: break-glass grants at a project scope and must not become a vehicle
// for install-wide super-user.
func TestActivateBreakGlass_RejectsInstallAdminEmergencyRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "admin", 4*time.Hour, 24*time.Hour) // admin is an install-wide role

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	_, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "install-wide administration")
}
