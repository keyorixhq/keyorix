// concurrency_sso_user_link_postgres_test.go — #2699.
//
// resolveSSOUser's first-federation path read the user with GetUserByEmail
// (unlocked, outside any transaction), set ExternalID on the struct, and
// persisted it with LocalStorage.UpdateUser — a bare GORM Save. Against a user
// an admin deleted after that read, Save's `UPDATE ... WHERE deleted_at IS
// NULL` matched 0 rows and its upsert fallback (`INSERT ... ON CONFLICT (id) DO
// UPDATE SET <every column>`) wrote `deleted_at = NULL, is_active = true,
// account_state = active` — the deleted account came back. CompleteSSO's
// login gate (sso.go, `!user.IsActive || AccountLoginBlocked(...)`) then
// evaluated A's STALE in-memory struct, which still said active, so the login
// proceeded and a session was minted for an account the admin had just
// deleted. The user controls the timing: they fire the first SSO login.
//
// Reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package) —
// see that file's header for what the GORM-callback interleaving technique
// does and does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_ResolveSSOUser_vs_DeleteUser_CrossReplicaPostgres asserts both
// halves of the defect, because fixing only the write would leave the login
// still happening:
//
//	(a) the row must STAY deleted — the write must not resurrect it;
//	(b) resolveSSOUser must not hand its caller a user that CompleteSSO's own
//	    gate would accept. That is the half that turns a resurrected row into
//	    an issued session, and it is a property of the returned value, not of
//	    the row, so (a) alone does not cover it.
func TestCTAReview_ResolveSSOUser_vs_DeleteUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	u := f.user("ssolink2699", "")
	require.Empty(t, u.ExternalID, "the fixture user must be never-federated, so resolveSSOUser takes the claim path")

	// Replica B's admin DeleteUser commits between A's unlocked read of the
	// user and A's own write of external_id.
	var delErr error
	fired := f.beforeA("update", "users", func() {
		delErr = f.coreB.DeleteUser(f.ctx, f.adminID, u.ID)
	})

	resolved, rerr := f.coreA.resolveSSOUser(f.ctx, "okta", "sub-2699", "ssolink2699@example.com", true)

	require.True(t, fired(), "replica A never reached its users UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	// (a) The row stays deleted.
	assert.Equal(t, int64(1), f.countLive(&models.User{}, "id = ? AND deleted_at IS NOT NULL", u.ID),
		"a delete that returned success must stay deleted: resolveSSOUser's write must not resurrect the row (resolve err: %v)", rerr)

	// (b) Nothing login-capable may come back. This is CompleteSSO's own gate,
	// evaluated on exactly what resolveSSOUser returned.
	if rerr == nil && resolved != nil {
		loginCapable := resolved.IsActive && !AccountLoginBlocked(resolved.ID, resolved.AccountState)
		assert.False(t, loginCapable,
			"resolveSSOUser returned a user CompleteSSO's gate would accept (is_active=%v account_state=%q) for an account deleted on another replica — a session would be minted",
			resolved.IsActive, resolved.AccountState)
	}
}
