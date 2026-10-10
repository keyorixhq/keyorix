// concurrency_credential_under_suspend_postgres_test.go — #2701.
//
// Suspending, deactivating or deleting a user sweeps exactly two child tables:
// `sessions` (DeleteSessionsForUserExcept) and `personal_access_tokens`
// (RevokeAllPersonalAccessTokensForUser), inside a transaction that row-locks
// the user first (LockUserForUpdate). The INSERTS were not serialized against
// that sweep, so a credential minted in the window committed with
// revoked=false / no rotated_at — after a sweep that was audited as complete.
//
// Why that is more than cosmetic, and why it is a PAT test rather than a
// session one: the PAT is inert while the account is blocked (pat.go re-checks
// account state), but ReactivateUser revokes nothing. So the sequence
// suspend → investigate → reactivate — an entirely routine one — leaves a PAT
// live that the "revoke all credentials" step was recorded as having removed,
// possibly with no expiry. The whole point of sweeping on suspend is that an
// operator can rely on it.
//
// Reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package);
// see that file's header for what the GORM-callback interleaving technique
// does and does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCTAReview_CreatePAT_vs_SuspendUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("pat2701", "")

	// Replica B suspends the user (locking the row and sweeping sessions + PATs)
	// between replica A's authorization and A's own PAT insert.
	var suspendErr error
	fired := f.beforeA("create", "personal_access_tokens", func() {
		suspendErr = f.coreB.SuspendUser(f.ctx, f.adminID, u.ID)
	})

	_, patErr := f.coreA.CreateOwnPAT(f.ctx, u.ID, "ci", nil, nil, 0, 0, nil)

	require.True(t, fired(), "replica A never reached its PAT INSERT — the interleaving under test never happened")
	require.NoError(t, suspendErr, "replica B's suspend must report success; the whole point is that it did")

	// The effect that matters: no unrevoked PAT may survive a sweep that was
	// reported complete. Asserted on the row rather than on patErr, because
	// CreateOwnPAT is allowed either to fail or to succeed-then-be-swept — what
	// it may not do is leave a live credential behind.
	assert.Zero(t, f.countLive(&models.PersonalAccessToken{}, "user_id = ? AND revoked = ?", u.ID, false),
		"a suspend that revoked all PATs and returned success must leave none unrevoked — otherwise "+
			"suspend → investigate → reactivate restores a credential the revoke-all was audited as having "+
			"removed (create err: %v)", patErr)
}

func TestCTAReview_CreateSession_vs_SuspendUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("sess2701", "")

	var suspendErr error
	fired := f.beforeA("create", "sessions", func() {
		suspendErr = f.coreB.SuspendUser(f.ctx, f.adminID, u.ID)
	})

	_, _, loginErr := f.coreA.Login(f.ctx, &LoginRequest{Username: "sess2701", Password: "UserPass123!xyz-long-enough"})

	require.True(t, fired(), "replica A never reached its session INSERT — the interleaving under test never happened")
	require.NoError(t, suspendErr, "replica B's suspend must report success; the whole point is that it did")

	assert.Zero(t, f.countLive(&models.Session{}, "user_id = ? AND rotated_at IS NULL", u.ID),
		"a suspend that terminated every session and returned success must leave none live — otherwise the "+
			"session becomes usable again the moment the account is reactivated, up to its own expiry "+
			"(login err: %v)", loginErr)
}

// DeleteUser is the sweep a weaker "fail only if the owner exists and is
// blocked" re-check would silently stop covering: a soft-deleted user reads as
// absent under GORM's default scoping. delete → restore → reactivate is the
// revival path here.
func TestCTAReview_CreatePAT_vs_DeleteUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("patdel2701", "")

	var deleteErr error
	fired := f.beforeA("create", "personal_access_tokens", func() {
		deleteErr = f.coreB.DeleteUser(f.ctx, f.adminID, u.ID)
	})

	_, patErr := f.coreA.CreateOwnPAT(f.ctx, u.ID, "ci", nil, nil, 0, 0, nil)

	require.True(t, fired(), "replica A never reached its PAT INSERT — the interleaving under test never happened")
	require.NoError(t, deleteErr, "replica B's delete must report success; the whole point is that it did")

	assert.Zero(t, f.countLive(&models.PersonalAccessToken{}, "user_id = ? AND revoked = ?", u.ID, false),
		"a delete that revoked all PATs and returned success must leave none unrevoked — otherwise "+
			"delete → restore → reactivate restores a credential the sweep was audited as having removed "+
			"(create err: %v)", patErr)
}
