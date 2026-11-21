// cta_review_grant_acl_vs_remove_member_postgres_test.go — #4533, the second variant
// #2649 names: GrantSecretACL racing RemoveProjectMember(grantee). #2785 closed the
// DeleteSecret half; this half is closed by the membership re-check in
// LocalStorage.CreateOrUpdateSecretACL (FOR SHARE on the grantee's live direct project
// grants, then the write, then the membership question again, in the upsert's own
// transaction). The two forced tests pin the window before A's membership lock and the
// one after A's upsert; the unforced loop at the end lets the database pick the
// ordering. The lock-order tests (re-grant, grant to the owner) are in
// cta_review_regrant_acl_vs_remove_member_postgres_test.go.
//
// Bug origin (#4533):
//
//	Introduced-by: GrantSecretACL's IsProjectMember-then-upsert, never serialized
//	  against RemoveProjectMember's RemoveAllProjectRoleGrants + CWE-284 ACL cascade
//	  (project_members.go), which deletes only the grants visible to its own transaction.
//	Detected-by: LIVENESS-IN-TX-NOV-1 (#4534), REVIEW-4534-DEEP-1 (listing impact)
//	Class: cross-replica check-then-act (race)
//	Severity: low-medium (a removed member keeps listing the secret's metadata; the
//	  grant is live again on re-add)
//	Guard: the three tests here, TestGrantSecretACL_MembershipRemovedBeforeUpsert_RefusedWithoutARow
//	  (SQLite, default CI) and TestLocalACL_RefusesNonMemberGrantee; the storage
//	  re-check itself is the mechanism, in the same transaction as the write.
package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres: B's
// RemoveProjectMember commits between A's membership check and A's ACL upsert. B's
// DeleteSecretACLsByUserAndProject ran before the grant existed, so the grant commits
// for a non-member. Authorization stays denied while they are out (HasSecretACL and
// batchACLStage re-check membership, #G13), but the row is not inert:
// ListSecretsWithSharingInfo's ACL source (applyACLGrant) does not re-check membership,
// so the removed user still lists the secret's metadata (for a folder grant, every
// descendant), and the grant is live again when an admin re-adds them. Neither serial
// order leaves an ACL row for a removed member, which is the invariant asserted here;
// the listing and re-add checks below make the eventual fix prove both consequences.
//
// B runs synchronously inside A's GORM hook, immediately before A's FOR SHARE on the
// grantee's user_roles (which precedes the upsert since REVIEW-4557-DEEP-1 MEDIUM-1):
// the latest point B can still commit first. A holds no lock B needs there; a hook
// after that lock would hang (B queues behind A), see the AfterUpsert test below.
func TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-aclmember", "project_viewer")
	s := f.secret("cta-aclmember-secret", f.adminID)

	var errB error
	fired := f.aroundALockingRead(false, "user_roles", func() {
		errB = f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee.ID)
	})
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	t.Logf("GrantSecretACL (A) err=%v, RemoveProjectMember (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's RemoveProjectMember before A's membership lock and upsert")
	require.NoError(t, errB)
	assert.Error(t, errA, "A must fail closed: its grantee was removed before it locked the membership rows")

	assert.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee.ID),
		"CWE-284: an ACL grant survives for a user removed from the project")

	// While removed, the stale grant must not list the secret's metadata either.
	listed, err := f.setup.ListSecretsWithSharingInfo(f.ctx, grantee.ID, &models.SecretListFilter{})
	require.NoError(t, err)
	for _, ls := range listed.Secrets {
		assert.NotEqual(t, s.ID, ls.ID, "a removed member still lists an ACL-granted secret's metadata")
	}

	// The consequence: re-adding the member brings the removed grant back.
	role, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRole(f.ctx, grantee.ID, role.ID, Scope{ProjectID: f.projectID}))
	ok, err := f.setup.HasSecretACL(f.ctx, grantee.ID, s.ID, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok, "re-adding a removed member reactivated an ACL grant the removal revoked")
}

// TestCTAReview_GrantSecretACL_RemoveProjectMemberAfterUpsert_CrossReplicaPostgres:
// B's RemoveProjectMember starts after A's ACL upsert ran but before A commits, when
// B's cascade cannot see A's row. Before the #4533 fix B committed there and the row
// survived; with the first fix B committed and A's check after the write refused.
// Since A's user_roles FOR SHARE precedes the upsert, B's DELETE must queue behind A,
// so A commits and B's cascade (a fresh snapshot) then sweeps the grant. B runs on its
// own goroutine (synchronously it would hang on A's lock).
func TestCTAReview_GrantSecretACL_RemoveProjectMemberAfterUpsert_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-aclmember-after", "project_viewer")
	s := f.secret("cta-aclmember-after-secret", f.adminID)

	var waitB func() (bool, error)
	fired := f.afterA("create", "secret_acls", func() {
		waitB = f.startUntilBlocked(func() error {
			return f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee.ID)
		})
	})
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	require.True(t, fired(), "the hook must have started B's RemoveProjectMember after A's ACL upsert")
	blocked, errB := waitB()
	t.Logf("GrantSecretACL (A) err=%v, RemoveProjectMember (B) err=%v, B blocked on A=%v", errA, errB, blocked)
	require.NoError(t, errB)

	assert.True(t, blocked, "B must have queued behind A's lock on the grantee's user_roles")
	assert.NoError(t, errA, "B waited for A, so A's grant commits and is then swept")
	assert.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee.ID),
		"CWE-284: an ACL grant survives for a user removed from the project")
}

// TestLivenessRace_GrantSecretACL_vs_RemoveProjectMember_Postgres: the unforced
// half (see cta_review_liveness_race_loop_postgres_test.go for the method). A fresh
// member per round; A grants, B removes the member, released from a barrier with
// B's start swept across A's solo duration. The invariant under every legal
// interleaving: once B's removal has committed, no ACL row exists for the removed
// member. A may win (and be swept by B's cascade, which then waited on A's FOR SHARE)
// or fail closed; both must occur or the loop raced nothing.
func TestLivenessRace_GrantSecretACL_vs_RemoveProjectMember_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s := f.secret("race-aclmember-secret", f.adminID)
	grant := func(userID uint) error {
		return f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, userID, []string{"secrets.read"})
	}
	n := 0
	solo := timeSolo(func() {
		n++
		require.NoError(t, grant(f.user(fmt.Sprintf("race-aclmember-solo-%d", n), "project_viewer").ID))
	})
	// B's removal (named lock, last-admin guard, assignment listing, then the
	// transaction) runs far longer before its DELETE than A's whole grant, so the
	// default quarter-of-A lead never let B's removal land before A's lock: 50 of
	// 50 rounds A won (measured at introduction). Lead B by its own solo duration
	// instead, so the early rounds see B commit around A's start and the sweep
	// crosses A's window from the other side too.
	m := 0
	soloB := timeSolo(func() {
		m++
		u := f.user(fmt.Sprintf("race-aclmember-rm-solo-%d", m), "project_viewer")
		require.NoError(t, f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, u.ID))
	})
	var tally raceTally
	for i := range livenessRaceRounds {
		grantee := f.user(fmt.Sprintf("race-aclmember-%d", i), "project_viewer")
		var errA, errB error
		raceFromBarrier(raceOffsetFrom(i, solo, soloB),
			func() { errA = grant(grantee.ID) },
			func() { errB = f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee.ID) },
		)
		require.NoError(t, errB, "round %d: RemoveProjectMember", i)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee.ID),
			"round %d (GrantSecretACL err=%v): CWE-284, an ACL grant exists for a removed member", i, errA)
	}
	tally.requireBothOutcomes(t, "GrantSecretACL")
}
