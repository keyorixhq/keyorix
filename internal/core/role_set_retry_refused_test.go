package core

// role_set_retry_refused_test.go — #3684: a PartialMutationError whose commit 2 was
// refused on the actor's own authority says retry_safe false (RetryRefused).

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// TestReplaceUserRoleSet_CeilingLostBetweenCommits_NotRetrySafe: the actor's own
// roles.assign is revoked by someone else after commit 1 and before commit 2. The
// removals stand (a revocation is never rolled back) and the answer says so, but it
// must not claim the retry is safe: the retry is refused.
func TestReplaceUserRoleSet_CeilingLostBetweenCommits_NotRetrySafe(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}
		admin, err := w.f.setup.Storage().GetRoleByName(ctx, "project_admin")
		require.NoError(t, err)

		a := w.newUser("race-a", "project_admin")
		w.newUser("race-b", "project_admin")
		target := w.newUser("race-t", "project_developer")

		commit2Lock := sodGrantLockKey("user", target.ID)
		c := NewKeyorixCore(hooked(w.fs, &storeHooks{
			WithNamedLock: func(next storage.Storage, ctx context.Context, key string, fn func(context.Context) error) error {
				if key == commit2Lock {
					// A concurrent revocation of the actor's admin role lands here.
					require.NoError(t, w.f.setup.Storage().RemoveRole(ctx, a.ID, admin.ID, scope))
				}
				return next.WithNamedLock(ctx, key, fn)
			},
		}))

		err = c.SetUserRoles(ctx, a.ID, target.ID, []uint{w.viewerRole.ID}, scope, false)
		pe, ok := AsPartialMutationError(err)
		require.True(t, ok, "the removal committed, so the answer must say so: %v", err)
		require.True(t, pe.RetryRefused)
		require.Equal(t, false, pe.Details()["retry_safe"], "a retry is refused: it is not retry-safe")
		require.Equal(t, "false", pe.Metadata()["retry_safe"])
		require.False(t, strings.Contains(pe.ClientMessage(), "retry the same request"))
		require.Empty(t, w.exactRoles(target.ID, scope), "the removal stands, the addition did not happen")

		// The audit-outage shape keeps retry_safe true.
		require.Equal(t, true, (&PartialMutationError{Applied: "x", NotApplied: "y", Err: ErrMutationAuditUnavailable}).Details()["retry_safe"])
	})
}
