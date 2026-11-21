// cta_review_regrant_acl_vs_remove_member_postgres_test.go — REVIEW-4557-DEEP-1
// MEDIUM-1, the lock order of the #4533 fix. The first version of the membership
// re-check in LocalStorage.CreateOrUpdateSecretACL locked the grantee's user_roles rows
// AFTER the upsert and the node lock, while RemoveProjectMember locks user_roles first
// (DELETE), then owned secret_nodes (UPDATE), then the ACL rows (DELETE). Two cycles
// followed on Postgres, and the deadlock detector could abort the removal (reproduced,
// 40P01, the member kept their roles and the grant):
//   - a re-grant: the upsert updates an existing ACL row, so A holds that row and waits
//     for user_roles while B holds user_roles and waits for the row;
//   - a grant to the secret's owner: A holds the node FOR SHARE and waits for
//     user_roles while B holds user_roles and waits for the node in its ownership UPDATE.
//
// The fix takes the membership lock first, so both transactions lock user_roles first:
// B either waits for A to commit and then sweeps the grant, or A waits for B and the
// membership check after the write refuses. The tests here require the removal to
// succeed and leave no ACL row in both shapes, plus the unforced re-grant loop.
//
// Bug origin (REVIEW-4557-DEEP-1 MEDIUM-1):
//
//	Introduced-by: #4557 (first head), lockDirectProjectGrants called after the upsert
//	Detected-by: REVIEW-4557-DEEP-1 (kpg probe: "deadlock detected (SQLSTATE 40P01)")
//	Class: lock-order inversion (deadlock) on a revocation path
//	Severity: medium (an offboarding removal can be made to fail; fails closed)
//	Guard: the three tests here and the reworked forced tests in
//	  cta_review_grant_acl_vs_remove_member_postgres_test.go
package core

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// aroundALockingRead registers a one-shot hook on replica A's own *gorm.DB around A's
// first locking read (SELECT ... FOR SHARE / FOR UPDATE) of table: before the statement
// executes, or (after == true) once it has executed and the lock is held. Like beforeA
// and afterA, it reports whether it fired so a test cannot pass vacuously.
func (f *ctaReview) aroundALockingRead(after bool, table string, concurrent func()) (fired func() bool) {
	f.t.Helper()
	var once sync.Once
	hit := false
	fn := func(tx *gorm.DB) {
		if tx.Statement.Table != table || tx.Error != nil {
			return
		}
		if _, locking := tx.Statement.Clauses["FOR"]; !locking {
			return
		}
		once.Do(func() {
			hit = true
			concurrent()
		})
	}
	if after {
		require.NoError(f.t, f.dbA.Callback().Query().After("gorm:query").Register("cta-review:after-lock-"+table, fn))
	} else {
		require.NoError(f.t, f.dbA.Callback().Query().Before("gorm:query").Register("cta-review:before-lock-"+table, fn))
	}
	return func() bool { return hit }
}

// rowLockWaiters is lockWaiters narrowed to row-lock waits (a tuple or another
// transaction's id). An advisory-lock wait does not count: the fixtures of parallel
// tests share one database, and their named locks (project guard keys) collide, so a
// plain Lock wait can be B queueing behind another test rather than behind A.
func (f *ctaReview) rowLockWaiters() int64 {
	f.t.Helper()
	var n int64
	require.NoError(f.t, f.setupDB.Raw(
		"SELECT count(*) FROM pg_stat_activity WHERE application_name = ? AND wait_event_type = 'Lock' AND wait_event IN ('transactionid', 'tuple')",
		f.appName).Scan(&n).Error)
	return n
}

// startUntilBlocked runs b (replica B's operation) on its own goroutine and returns as
// soon as one of this fixture's backends is waiting on a row lock, or b has finished,
// or 10s have passed. Use it from inside A's hook where B must queue behind a row lock
// A holds: running B synchronously there would hang. wait returns whether B was seen
// blocked and B's error, after B finishes.
func (f *ctaReview) startUntilBlocked(b func() error) (wait func() (blocked bool, err error)) {
	f.t.Helper()
	done := make(chan error, 1)
	go func() { done <- b() }()
	blocked := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-done:
			return func() (bool, error) { return false, err }
		default:
		}
		if f.rowLockWaiters() > 0 {
			blocked = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func() (bool, error) { return blocked, <-done }
}

// TestCTAReview_ReGrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres: cycle (a).
// The grantee already holds a grant; B's RemoveProjectMember starts right after A's
// upsert (an UPDATE of the existing row) and must queue behind A, then remove the
// member and sweep the grant. With the lock-after-write order B was the side Postgres
// aborted.
func TestCTAReview_ReGrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-regrant", "project_viewer")
	s := f.secret("cta-regrant-secret", f.adminID)
	require.NoError(t, f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"}))

	var waitB func() (bool, error)
	fired := f.afterA("create", "secret_acls", func() {
		waitB = f.startUntilBlocked(func() error {
			return f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee.ID)
		})
	})
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read", "secrets.write"})
	require.True(t, fired(), "the hook must have started B's RemoveProjectMember after A's ACL upsert")
	blocked, errB := waitB()
	t.Logf("GrantSecretACL (A) err=%v, RemoveProjectMember (B) err=%v, B blocked on A=%v", errA, errB, blocked)

	require.NoError(t, errB, "the removal must not be aborted (40P01) by a concurrent re-grant")
	require.True(t, blocked, "B must have queued behind A's lock on the grantee's user_roles")
	require.NoError(t, errA, "B waited for A, so A's re-grant commits and is then swept")
	require.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee.ID),
		"CWE-284: an ACL grant survives for a user removed from the project")
}

// TestCTAReview_GrantSecretACLToOwner_vs_RemoveProjectMember_CrossReplicaPostgres:
// cycle (b). The grantee owns the secret, so the removal's ClearProjectSecretOwnership
// UPDATEs the node A holds FOR SHARE. B starts once A holds that node lock.
func TestCTAReview_GrantSecretACLToOwner_vs_RemoveProjectMember_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-grant-owner", "project_viewer")
	s := f.secret("cta-grant-owner-secret", grantee.ID)

	var waitB func() (bool, error)
	fired := f.aroundALockingRead(true, "secret_nodes", func() {
		waitB = f.startUntilBlocked(func() error {
			return f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee.ID)
		})
	})
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	require.True(t, fired(), "the hook must have started B's RemoveProjectMember once A held the node FOR SHARE")
	blocked, errB := waitB()
	t.Logf("GrantSecretACL (A) err=%v, RemoveProjectMember (B) err=%v, B blocked on A=%v", errA, errB, blocked)

	require.NoError(t, errB, "the removal must not be aborted (40P01) by a concurrent grant to the secret's owner")
	require.True(t, blocked, "B must have queued behind A's locks")
	require.NoError(t, errA, "B waited for A, so A's grant commits and is then swept")
	require.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee.ID),
		"CWE-284: an ACL grant survives for a user removed from the project")
	var owner []uint
	require.NoError(t, f.setupDB.Model(&models.SecretNode{}).Where("id = ?", s.ID).Pluck("owner_id", &owner).Error)
	require.Equal(t, []uint{0}, owner, "the removal must have cleared the removed member's ownership")
}

// TestLivenessRace_ReGrantSecretACL_vs_RemoveProjectMember_Postgres: the unforced
// re-grant loop, TestLivenessRace_GrantSecretACL_vs_RemoveProjectMember_Postgres with
// a grant before each round, so every racing upsert updates an existing row (the shape
// that deadlocked). Every round requires the removal to succeed and leave no ACL row.
func TestLivenessRace_ReGrantSecretACL_vs_RemoveProjectMember_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s := f.secret("race-regrant-secret", f.adminID)
	grant := func(userID uint, perms ...string) error {
		return f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, userID, perms)
	}
	member := func(name string) uint {
		u := f.user(name, "project_viewer")
		require.NoError(t, grant(u.ID, "secrets.read"))
		return u.ID
	}
	n := 0
	var soloUsers []uint
	for range 3 {
		soloUsers = append(soloUsers, member(fmt.Sprintf("race-regrant-solo-%d", len(soloUsers))))
	}
	solo := timeSolo(func() {
		require.NoError(t, grant(soloUsers[n], "secrets.read", "secrets.write"))
		n++
	})
	m := 0
	soloB := timeSolo(func() {
		m++
		u := member(fmt.Sprintf("race-regrant-rm-solo-%d", m))
		require.NoError(t, f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, u))
	})
	var tally raceTally
	for i := range livenessRaceRounds {
		grantee := member(fmt.Sprintf("race-regrant-%d", i))
		var errA, errB error
		raceFromBarrier(raceOffsetFrom(i, solo, soloB),
			func() { errA = grant(grantee, "secrets.read", "secrets.write") },
			func() { errB = f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee) },
		)
		require.NoError(t, errB, "round %d: RemoveProjectMember (GrantSecretACL err=%v)", i, errA)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee),
			"round %d (GrantSecretACL err=%v): CWE-284, an ACL grant exists for a removed member", i, errA)
	}
	tally.requireBothOutcomes(t, "re-GrantSecretACL")
}
