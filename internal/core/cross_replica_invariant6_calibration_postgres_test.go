// cross_replica_invariant6_calibration_postgres_test.go — calibration for
// FuzzCrossReplicaInvariants' invariant 6 (g4OrphanedMembershipGrants), the
// oracle for INV-CORE-44 / the #2657+#2659 class.
//
// Why this file exists. #2669 fixed #2657 and #2659 for real — both paths now
// run their membership state change and their grant side effect under
// WithNamedLock(membershipLockKey(project, user)), and the two named
// demonstrations in concurrency_check_then_act_exempt_review_postgres_test.go
// pass. #2659's fuzz seed kept failing anyway, and it was the ORACLE that was
// wrong, not the code: invariant 6 was
//
//	project_memberships m JOIN user_roles ur
//	  ON ur.user_id = m.user_id AND ur.project_id = m.project_id
//	WHERE m.state = 'revoked'
//
// which is not INV-CORE-44 ("the grant THAT membership conferred") but a
// strictly stronger claim, and the stronger claim is false under plain serial
// execution — see TestInvariant6_SoundOnSerialReinvite.
//
// An oracle that was loosened to stop a false positive is worthless unless it
// still catches the thing it is named for, so this file calibrates BOTH
// directions, which is the whole point of having it:
//
//	soundness   — TestInvariant6_SoundOnSerialReinvite: must NOT fire on a
//	              state any serial execution can reach (zero goroutines).
//	sensitivity — TestInvariant6_FiresOnOrphanedGrantEndState: must fire on
//	              the #2659 end state, built by construction (zero goroutines,
//	              so this one can never go flaky).
//	sensitivity — TestInvariant6_MembershipLockIsLoadBearing_OpenModeInvite
//	              and ..._Activate: remove membershipLockKey from one replica
//	              in BOTH its forms (the WithNamedLock section and the
//	              LockNamedKeyInTx fence key, NAMEDLOCK-OVERLAP-2), force the
//	              real interleaving, and confirm the predicate reports the
//	              violation. These also re-prove that the membership key is
//	              load-bearing rather than decorative.
//	fence       — TestInvariant6_MembershipFenceSurvivesLostNamedLock_*:
//	              remove only the WithNamedLock section (the lock-loss window
//	              NAMEDLOCK-OVERLAP-2 is about) and run B's revoke concurrent
//	              with, or before, A's fence: invariant 6 must stay empty and
//	              the revoke must win.
//
// Postgres only, same KEYORIX_TEST_PG_DSN gate as every other
// concurrency_*_postgres_test.go in this package.
package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// legacyInvariant6Join is the cross-row join invariant 6 used to be. It is
// kept ONLY so the soundness test can assert that the state it builds is
// genuinely the state that used to produce a false positive — without it,
// TestInvariant6_SoundOnSerialReinvite could pass vacuously (e.g. if the
// fixture stopped producing two membership rows at all) and nobody would
// notice the calibration had stopped calibrating anything.
func legacyInvariant6Join(t *testing.T, f *ctaReview) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.setupDB.Raw(
		"SELECT count(*) FROM project_memberships m JOIN user_roles ur ON ur.user_id = m.user_id AND ur.project_id = m.project_id WHERE m.state = 'revoked'",
	).Scan(&n).Error)
	return n
}

// noNamedLockStorage turns every WithNamedLock into a direct call, which on
// replica A removes the membershipLockKey section #2669 added and takes the
// whole family with it: the shape of a replica whose named lock was lost
// (NAMEDLOCK-OVERLAP-1's window). Same approach, and the same reason, as
// noRowLockStorage's own WithNamedLock override
// (concurrency_scim_account_state_race_postgres_test.go): proving the
// property holds when the guard is missing is the point, and a wrapper that
// strips the entire family is simpler to reason about than one that strips a
// key prefix. lockInTx, when non-nil, replaces LockNamedKeyInTx (the
// transaction-scoped fence keys, NAMEDLOCK-OVERLAP-2); nil leaves the fence
// keys real.
//
// pg_advisory_lock keys live in the DATABASE, while this package's Postgres
// fixtures isolate only the SCHEMA (pgIsolatedSchemaDSN), and every ctaReview
// fixture bootstraps the same IDs — so "project-membership:2:2" and
// "sod-grant:user:2" are literally the same advisory locks in every parallel
// test in the package. With replica A holding one of them across a
// synchronous hook, A, replica B and an unrelated parallel test formed a
// three-way cycle (observed: two tests hung past a 10-minute timeout), and
// since NAMEDLOCK-OVERLAP-2 A's grant transaction holds the membership key
// itself (membershipActiveFence), so a B run synchronously inside that
// transaction waits on A forever. So B never runs synchronously while A holds
// a key B takes: it runs in a goroutine (beforeACreateUntilBlockedOnA), or
// synchronously only before A's fence takes the key (revokeBeforeMembershipFence).
func noNamedLockStorage(inner storage.Storage, lockInTx func(next storage.Storage, ctx context.Context, key string) error) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		WithNamedLock: func(_ storage.Storage, ctx context.Context, _ string, fn func(ctx context.Context) error) error {
			return fn(ctx)
		},
		LockNamedKeyInTx: lockInTx,
	})
}

// noTxNamedKeys turns every LockNamedKeyInTx into a no-op: with noNamedLockStorage
// it removes membershipLockKey in both its forms, the pre-#2669 code shape.
func noTxNamedKeys(storage.Storage, context.Context, string) error { return nil }

// unlockedMembershipCore is replica A with membershipLockKey (and every other
// named lock and fence key) removed — the pre-#2669 code shape.
func unlockedMembershipCore(t *testing.T, f *ctaReview) *KeyorixCore {
	t.Helper()
	return namedLockLostCore(t, f, noTxNamedKeys)
}

// namedLockLostCore is replica A with every WithNamedLock section removed (its
// named lock lost) and LockNamedKeyInTx replaced by lockInTx (nil: the real
// fence keys).
func namedLockLostCore(t *testing.T, f *ctaReview, lockInTx func(next storage.Storage, ctx context.Context, key string) error) *KeyorixCore {
	t.Helper()
	c := NewKeyorixCore(noNamedLockStorage(localstore.NewLocalStorage(f.dbA), lockInTx))
	c.SetAuthEncryptor(f.enc)
	return c
}

// beforeACreateUntilBlockedOnA starts concurrent in a goroutine right before
// A's first INSERT into table and holds A there until concurrent has finished
// (it ran inside A's window: the unfenced interleaving) or Postgres reports a
// backend blocked by A's OWN backend (pg_blocking_pids: B waits on a lock A's
// transaction holds and runs after A commits). Same probe as
// beforeAShareUpdate: a waiter of a parallel test cannot release A early.
// blockedOnA reports which of the two happened; call waitB after A returns.
func (f *ctaReview) beforeACreateUntilBlockedOnA(table string, concurrent func()) (fired, blockedOnA func() bool, waitB func()) {
	f.t.Helper()
	var once sync.Once
	hit, blocked := false, false
	done := make(chan struct{})
	require.NoError(f.t, f.dbA.Callback().Create().Before("gorm:create").Register("inv6:before-create-"+table, func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		once.Do(func() {
			hit = true
			var pidA int64
			require.NoError(f.t, tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context, "SELECT pg_backend_pid()").Scan(&pidA))
			go func() {
				defer close(done)
				concurrent()
			}()
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				select {
				case <-done:
					return
				default:
				}
				var n int64
				require.NoError(f.t, f.setupDB.Raw("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))", pidA).
					Scan(&n).Error)
				if n > 0 {
					blocked = true
					return
				}
			}
			f.t.Errorf("B neither finished nor blocked on A within 10s")
		})
	}))
	return func() bool { return hit }, func() bool { return blocked }, func() {
		if hit {
			<-done
		}
	}
}

// revokeBeforeMembershipFence is a LockNamedKeyInTx hook for replica A that
// runs revoke synchronously right before A's nth LockNamedKeyInTx of key, then
// takes the key for real. For an activation the first such call is the state
// CAS and the second is membershipActiveFence; for an open-mode invite the
// first is the fence. A holds no lock B takes at that point (its named lock is
// lost and, the fence being the first statement of the grant transaction,
// nothing else in that transaction ran yet), so B runs to completion there.
func revokeBeforeMembershipFence(key string, nth int, revoke func()) (hook func(next storage.Storage, ctx context.Context, k string) error, fired func() bool) {
	calls, hit := 0, false
	return func(next storage.Storage, ctx context.Context, k string) error {
		if k == key {
			calls++
			if calls == nth {
				hit = true
				revoke()
			}
		}
		return next.LockNamedKeyInTx(ctx, k)
	}, func() bool { return hit }
}

// TestInvariant6_SoundOnSerialReinvite: `invite(open) → revoke → re-invite`
// is a legal SERIAL sequence — inviteMemberWithMode rejects only a
// NON-revoked membership (GetActiveProjectMembership is `state <> 'revoked'`),
// so once the first membership is revoked a fresh invite is allowed and
// correctly grants the role again. The end state therefore has a `revoked`
// row sitting beside an `active` row whose grant is live and legitimate.
//
// INV-CORE-44 is not violated: the revoked membership's own grant was removed
// when it was revoked, and the live grant belongs to the active membership.
// The old cross-row join could not express that and fired anyway, with no
// concurrency, no replicas and no interleaving involved — which is why
// #2659's seed kept failing after #2669 had genuinely fixed #2659.
//
// Red/green: with g4OrphanedMembershipGrants' body replaced by
// legacyInvariant6Join's query, this test fails (orphaned = 1).
func TestInvariant6_SoundOnSerialReinvite(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	f.setup.SetMembershipValidationMode(ValidationModeOpen)
	u := f.user("inv6-serial", "")

	m1, err := f.setup.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	require.NoError(t, err)
	require.Equal(t, MembershipActive, m1.State, "open mode must land the invite in active")

	revoked, err := f.setup.TransitionMembership(f.ctx, f.projectID, m1.ID, MembershipRevoked, f.adminID, false)
	require.NoError(t, err)
	require.Equal(t, MembershipRevoked, revoked.State)
	member, err := f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	require.False(t, member, "revoking the membership must remove the grant it conferred")

	m2, err := f.setup.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	require.NoError(t, err)
	require.Equal(t, MembershipActive, m2.State)
	require.NotEqual(t, m1.ID, m2.ID, "the re-invite must create a second membership row")

	member, err = f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	require.True(t, member, "the re-invite's own grant must be live")

	// Calibration guard: this really is the shape that fooled the old oracle.
	require.Positive(t, legacyInvariant6Join(t, f),
		"fixture no longer reproduces the cross-row-join false positive — this test would be vacuous")

	orphaned, err := g4OrphanedMembershipGrants(f.setupDB)
	require.NoError(t, err)
	assert.Empty(t, orphaned,
		"invariant 6 fired on a state reachable by a purely serial invite→revoke→re-invite: "+
			"the revoked membership's grant was removed and the live grant belongs to the active membership")
}

// TestInvariant6_FiresOnOrphanedGrantEndState: the oracle's positive control,
// built by construction rather than by racing, so it can never go flaky and
// can never be degraded by a missed timing window. This is the exact end
// state #2657/#2659 produce — a `revoked` membership, no other membership for
// the pair, and a live project-scope grant — and invariant 6 must report it.
//
// Without this test, correcting the predicate to stop the false positive
// would be indistinguishable from deleting the check.
func TestInvariant6_FiresOnOrphanedGrantEndState(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("inv6-orphan", "")

	_, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: u.ID, Role: "project_viewer", State: MembershipRevoked,
	})
	require.NoError(t, err)
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRole(f.ctx, u.ID, viewer.ID, Scope{ProjectID: f.projectID}))

	orphaned, err := g4OrphanedMembershipGrants(f.setupDB)
	require.NoError(t, err)
	require.NotEmpty(t, orphaned, "invariant 6 must fire on the #2657/#2659 end state")
	assert.Contains(t, orphaned, g4OrphanedGrant{UserID: u.ID, ProjectID: f.projectID})
}

// TestInvariant6_FiresOnOrphanedGrantUnderPendingReinvite: the gap an earlier
// form of the predicate had. It scoped the "nothing legitimately owns this
// grant" condition to "no NON-REVOKED membership remains", which a PENDING row
// also satisfies — so `revoke → invite(allowlist)` left a `revoked` row beside
// an `invited` row and the oracle went quiet, even though an `invited`
// membership confers no grant and therefore cannot be the grant's owner. A
// grant that outlived the revoke would have been missed.
//
// The predicate now requires that no `active` membership remains, which is the
// state that actually confers a grant (derived, not assumed:
// TestOnlyActiveMembershipStateConfersProjectGrant). This test plants the
// surviving grant explicitly rather than racing for it — the end state is what
// the oracle has to recognise, and building it directly keeps the test
// deterministic.
//
// Red/green: with the NOT EXISTS clause relaxed from `m2.state = 'active'` back
// to `m2.state <> 'revoked'`, this test fails (orphaned is empty).
func TestInvariant6_FiresOnOrphanedGrantUnderPendingReinvite(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("inv6-pending", "")

	// A real revoked membership, via the real paths.
	f.setup.SetMembershipValidationMode(ValidationModeOpen)
	m1, err := f.setup.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	require.NoError(t, err)
	_, err = f.setup.TransitionMembership(f.ctx, f.projectID, m1.ID, MembershipRevoked, f.adminID, false)
	require.NoError(t, err)
	member, err := f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	require.False(t, member, "the revoke must have removed the grant")

	// The #2657/#2659 defect: the grant outlives the revoke.
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRole(f.ctx, u.ID, viewer.ID, Scope{ProjectID: f.projectID}))

	// A re-invite in a NON-open mode lands pending, conferring nothing.
	f.setup.SetMembershipValidationMode(ValidationModeAllowlist)
	m2, err := f.setup.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	require.NoError(t, err)
	require.Equal(t, MembershipInvited, m2.State, "allowlist mode must land the re-invite pending")
	require.NotEqual(t, m1.ID, m2.ID)

	orphaned, err := g4OrphanedMembershipGrants(f.setupDB)
	require.NoError(t, err)
	assert.Contains(t, orphaned, g4OrphanedGrant{UserID: u.ID, ProjectID: f.projectID},
		"a pending membership confers no grant, so it must not shield a grant that outlived the revoke")
}

// TestOnlyActiveMembershipStateConfersProjectGrant derives the premise
// g4OrphanedMembershipGrants rests on — that `active` is the ONLY membership
// state conferring a project-scope role grant — behaviourally, from the real
// paths, rather than restating it.
//
// It covers both ways a membership reaches a state: every validation mode's
// initial state (inviteMemberWithMode) and every state reachable by stepping
// the machine (TransitionMembership). The subtest set is checked against
// membershipTransitions' own key set, so a newly added state cannot slip
// through uncovered — if someone adds a sixth state, or makes `provisioned`
// confer a grant, this fails instead of quietly blinding invariant 6.
func TestOnlyActiveMembershipStateConfersProjectGrant(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)

	grantHeld := func(userID uint) bool {
		t.Helper()
		var n int64
		require.NoError(t, f.setupDB.Raw(
			"SELECT count(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND project_id = ?",
			userID, viewer.ID, f.projectID).Scan(&n).Error)
		return n > 0
	}

	seen := map[string]bool{}

	// (a) initial states, one per validation mode.
	for _, tc := range []struct {
		name        string
		mode        string
		idpResolved bool
		wantState   string
	}{
		{"open", ValidationModeOpen, false, MembershipActive},
		{"allowlist", ValidationModeAllowlist, false, MembershipInvited},
		{"idp-resolved", ValidationModeIDP, true, MembershipProvisioned},
		{"idp-unresolved", ValidationModeIDP, false, MembershipInvited},
	} {
		u := f.user("inv6-mode-"+tc.name, "")
		f.setup.SetMembershipValidationMode(tc.mode)
		m, err := f.setup.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, tc.idpResolved)
		require.NoError(t, err, "mode %s", tc.name)
		require.Equal(t, tc.wantState, m.State, "mode %s initial state", tc.name)
		seen[m.State] = true
		assert.Equal(t, m.State == MembershipActive, grantHeld(u.ID),
			"mode %s landed in %s: a project grant must exist iff that state is %s", tc.name, m.State, MembershipActive)
	}

	// (b) every state reachable by stepping the machine, walked end to end.
	walker := f.user("inv6-walk", "")
	m, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: walker.ID, Role: "project_viewer", State: MembershipInvited,
	})
	require.NoError(t, err)
	seen[MembershipInvited] = true
	require.False(t, grantHeld(walker.ID), "a freshly invited membership confers nothing")

	for _, to := range []string{MembershipIdentityVerified, MembershipProvisioned, MembershipActive, MembershipRevoked} {
		require.True(t, canTransition(m.State, to), "walk assumes %s → %s is legal", m.State, to)
		got, err := f.setup.TransitionMembership(f.ctx, f.projectID, m.ID, to, f.adminID, false)
		require.NoError(t, err, "transition to %s", to)
		require.Equal(t, to, got.State)
		m = got
		seen[to] = true
		assert.Equal(t, to == MembershipActive, grantHeld(walker.ID),
			"membership in %s: a project grant must exist iff that state is %s", to, MembershipActive)
	}

	// Completeness: the walk above must have visited every declared state, so
	// a new one cannot be added without this test noticing.
	for state := range membershipTransitions {
		assert.True(t, seen[state],
			"membership state %q is declared in membershipTransitions but never exercised here — "+
				"extend this test, and re-check g4OrphanedMembershipGrants' NOT EXISTS clause if %q confers a grant", state, state)
	}
	assert.Len(t, seen, len(membershipTransitions), "states exercised: %v", seen)
}

// inv6MembershipOutcome reads the end state the invariant-6 tests judge: the
// membership's state, whether the user holds a project grant, and invariant 6's
// own verdict over the whole database.
func inv6MembershipOutcome(t *testing.T, f *ctaReview, membershipID, userID uint) (state string, member bool, orphaned []g4OrphanedGrant) {
	t.Helper()
	got, err := f.setup.Storage().GetProjectMembership(f.ctx, membershipID)
	require.NoError(t, err)
	member, err = f.setup.Storage().IsProjectMember(f.ctx, userID, f.projectID)
	require.NoError(t, err)
	orphaned, err = g4OrphanedMembershipGrants(f.setupDB)
	require.NoError(t, err)
	return got.State, member, orphaned
}

// TestInvariant6_MembershipLockIsLoadBearing_OpenModeInvite: the end-to-end
// mutation. Replica A runs the open-mode invite with membershipLockKey
// removed in both its forms (no WithNamedLock section, no LockNamedKeyInTx
// fence key: the pre-#2669 shape); replica B's revoke is forced to run, in
// full, on its own connection, immediately before A's user_roles INSERT. B
// finds no grant to remove, reports success, and A's grant then lands on a
// membership B has just revoked — #2659 exactly. Invariant 6 must report it.
//
// B runs in a goroutine and A waits until B finished or is blocked by A's
// own backend (beforeACreateUntilBlockedOnA). With both forms of the key
// removed nothing A holds stops B, so B must finish inside A's window; if it
// is blocked instead, A holds some other lock B needs, the interleaving is not
// the #2659 one, and the test fails on that instead of passing vacuously.
func TestInvariant6_MembershipLockIsLoadBearing_OpenModeInvite(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	coreA := unlockedMembershipCore(t, f)
	coreA.SetMembershipValidationMode(ValidationModeOpen)
	u := f.user("inv6-invitee", "")

	var errB error
	fired, blockedOnA, waitB := f.beforeACreateUntilBlockedOnA("user_roles", func() {
		m, err := f.coreB.Storage().GetActiveProjectMembership(f.ctx, f.projectID, u.ID)
		if err != nil {
			errB = err
			return
		}
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	created, errA := coreA.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	waitB()
	t.Logf("invite (A, no membership key) err=%v, revoke (B) err=%v, B blocked on A=%v", errA, errB, blockedOnA())
	require.True(t, fired(), "the hook must have run B's revoke before A's role-grant INSERT")
	require.False(t, blockedOnA(), "B must run inside A's window: A holds no membership key in this mutation")
	require.NoError(t, errA)
	require.NoError(t, errB, "the revoke itself reported success")

	state, member, orphaned := inv6MembershipOutcome(t, f, created.ID, u.ID)
	require.Equal(t, MembershipRevoked, state, "B's revoke must have won the membership row")
	require.True(t, member, "A's grant must have landed after the revoke — that is the #2659 bug")
	assert.Contains(t, orphaned, g4OrphanedGrant{UserID: u.ID, ProjectID: f.projectID},
		"invariant 6 must still report the real #2659 violation after being corrected")
}

// TestInvariant6_MembershipLockIsLoadBearing_Activate: the #2657 sibling, via
// TransitionMembership's provisioned→active path instead of the invite. Same
// mutation, same precondition, same required verdict.
func TestInvariant6_MembershipLockIsLoadBearing_Activate(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	coreA := unlockedMembershipCore(t, f)
	u := f.user("inv6-activate", "")
	m, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: u.ID, Role: "project_viewer", State: MembershipProvisioned,
	})
	require.NoError(t, err)

	var errB error
	fired, blockedOnA, waitB := f.beforeACreateUntilBlockedOnA("user_roles", func() {
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	_, errA := coreA.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipActive, f.adminID, false)
	waitB()
	t.Logf("activate (A, no membership key) err=%v, revoke (B) err=%v, B blocked on A=%v", errA, errB, blockedOnA())
	require.True(t, fired(), "the hook must have run B's revoke before A's role-grant INSERT")
	require.False(t, blockedOnA(), "B must run inside A's window: A holds no membership key in this mutation")
	require.NoError(t, errB, "the revoke itself reported success")

	state, member, orphaned := inv6MembershipOutcome(t, f, m.ID, u.ID)
	t.Logf("final membership state=%s, holds project grant=%v", state, member)
	require.Equal(t, MembershipRevoked, state, "B's revoke must have won the membership row")
	require.True(t, member, "A's grant must have landed after the revoke — that is the #2657 bug")
	assert.Contains(t, orphaned, g4OrphanedGrant{UserID: u.ID, ProjectID: f.projectID},
		"invariant 6 must still report the real #2657 violation after being corrected")
}

// TestInvariant6_MembershipFenceSurvivesLostNamedLock_OpenModeInvite_ConcurrentRevoke:
// the same forced interleaving as ..._MembershipLockIsLoadBearing_OpenModeInvite,
// with only the WithNamedLock section removed (A's named lock lost) and the
// fence key real. A's grant transaction holds membershipLockKey
// (membershipActiveFence) when B's revoke starts, so B's state CAS must wait for
// A's commit, and B's removal then sees A's grant and removes it: no orphaned
// grant, the revoke wins. Without the fence key this is the calibration above
// (B finishes inside A's window and the grant is orphaned).
func TestInvariant6_MembershipFenceSurvivesLostNamedLock_OpenModeInvite_ConcurrentRevoke(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	coreA := namedLockLostCore(t, f, nil)
	coreA.SetMembershipValidationMode(ValidationModeOpen)
	u := f.user("inv6-fence-invitee", "")

	var errB error
	fired, blockedOnA, waitB := f.beforeACreateUntilBlockedOnA("user_roles", func() {
		m, err := f.coreB.Storage().GetActiveProjectMembership(f.ctx, f.projectID, u.ID)
		if err != nil {
			errB = err
			return
		}
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	created, errA := coreA.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	waitB()
	t.Logf("invite (A, named lock lost) err=%v, revoke (B) err=%v, B blocked on A=%v", errA, errB, blockedOnA())
	require.True(t, fired(), "the hook must have started B's revoke before A's role-grant INSERT")
	require.True(t, blockedOnA(), "B's revoke must wait on A's grant transaction (it finished inside A's window: %v)", errB)
	require.NoError(t, errA, "A's invite held the membership key first and must commit")
	require.NoError(t, errB, "B's revoke runs after A's commit and must succeed")

	state, member, orphaned := inv6MembershipOutcome(t, f, created.ID, u.ID)
	require.Equal(t, MembershipRevoked, state, "the revoke must win the membership row")
	require.False(t, member, "a revoked membership kept its role grant")
	assert.Empty(t, orphaned, "invariant 6: no grant may outlive the revoke of the membership that conferred it")
}

// TestInvariant6_MembershipFenceSurvivesLostNamedLock_Activate_ConcurrentRevoke:
// the #2657 sibling of the test above (provisioned→active).
func TestInvariant6_MembershipFenceSurvivesLostNamedLock_Activate_ConcurrentRevoke(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	coreA := namedLockLostCore(t, f, nil)
	u := f.user("inv6-fence-activate", "")
	m, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: u.ID, Role: "project_viewer", State: MembershipProvisioned,
	})
	require.NoError(t, err)

	var errB error
	fired, blockedOnA, waitB := f.beforeACreateUntilBlockedOnA("user_roles", func() {
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	_, errA := coreA.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipActive, f.adminID, false)
	waitB()
	t.Logf("activate (A, named lock lost) err=%v, revoke (B) err=%v, B blocked on A=%v", errA, errB, blockedOnA())
	require.True(t, fired(), "the hook must have started B's revoke before A's role-grant INSERT")
	require.True(t, blockedOnA(), "B's revoke must wait on A's grant transaction (it finished inside A's window: %v)", errB)
	require.NoError(t, errA, "A's activation held the membership key first and must commit")
	require.NoError(t, errB, "B's revoke runs after A's commit and must succeed")

	state, member, orphaned := inv6MembershipOutcome(t, f, m.ID, u.ID)
	require.Equal(t, MembershipRevoked, state, "the revoke must win the membership row")
	require.False(t, member, "a revoked membership kept its role grant")
	assert.Empty(t, orphaned, "invariant 6: no grant may outlive the revoke of the membership that conferred it")
}

// TestInvariant6_MembershipFenceSurvivesLostNamedLock_OpenModeInvite_RevokeBeforeFence:
// A's named lock is lost and B's revoke commits in full after A created the
// `active` membership but before A's grant transaction takes the fence key.
// The fence's re-read then sees `revoked` and refuses the grant
// (ErrMembershipStateConflict, the grant transaction rolls back), and the
// refusal leaves B's revoked row alone: no orphaned grant, the revoke wins.
func TestInvariant6_MembershipFenceSurvivesLostNamedLock_OpenModeInvite_RevokeBeforeFence(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("inv6-prefence-invitee", "")

	var errB error
	var membershipID uint
	hook, fired := revokeBeforeMembershipFence(membershipLockKey(f.projectID, u.ID), 1, func() {
		m, err := f.coreB.Storage().GetActiveProjectMembership(f.ctx, f.projectID, u.ID)
		if err != nil {
			errB = err
			return
		}
		membershipID = m.ID
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	coreA := namedLockLostCore(t, f, hook)
	coreA.SetMembershipValidationMode(ValidationModeOpen)
	_, errA := coreA.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	t.Logf("invite (A, named lock lost) err=%v, revoke (B) err=%v", errA, errB)
	require.True(t, fired(), "B's revoke must have run before A's fence took the membership key")
	require.NoError(t, errB, "B's revoke commits before A's grant and must succeed")
	require.ErrorIs(t, errA, ErrMembershipStateConflict, "A's fence must refuse the grant on a membership B revoked")

	state, member, orphaned := inv6MembershipOutcome(t, f, membershipID, u.ID)
	require.Equal(t, MembershipRevoked, state, "the revoke must win the membership row")
	require.False(t, member, "A's refused grant must not have landed")
	assert.Empty(t, orphaned, "invariant 6: no grant may outlive the revoke of the membership that conferred it")
}

// TestInvariant6_MembershipFenceSurvivesLostNamedLock_Activate_RevokeBeforeFence:
// the #2657 sibling of the test above. A's state CAS (the first
// LockNamedKeyInTx of the key) committed `active`; B's revoke runs before A's
// fence (the second).
func TestInvariant6_MembershipFenceSurvivesLostNamedLock_Activate_RevokeBeforeFence(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("inv6-prefence-activate", "")
	m, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: u.ID, Role: "project_viewer", State: MembershipProvisioned,
	})
	require.NoError(t, err)

	var errB error
	hook, fired := revokeBeforeMembershipFence(membershipLockKey(f.projectID, u.ID), 2, func() {
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	coreA := namedLockLostCore(t, f, hook)
	_, errA := coreA.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipActive, f.adminID, false)
	t.Logf("activate (A, named lock lost) err=%v, revoke (B) err=%v", errA, errB)
	require.True(t, fired(), "B's revoke must have run before A's fence took the membership key")
	require.NoError(t, errB, "B's revoke commits before A's grant and must succeed")
	require.ErrorIs(t, errA, ErrMembershipStateConflict, "A's fence must refuse the grant on a membership B revoked")

	state, member, orphaned := inv6MembershipOutcome(t, f, m.ID, u.ID)
	require.Equal(t, MembershipRevoked, state, "the revoke must win the membership row (A's refusal must not revert it)")
	require.False(t, member, "A's refused grant must not have landed")
	assert.Empty(t, orphaned, "invariant 6: no grant may outlive the revoke of the membership that conferred it")
}
