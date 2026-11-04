package core

// role_set_ceiling_fault_not_refusal_test.go — PAT-SCOPE-TAILS-1 item 2 (#3840 review
// LOW): RetryRefused is only for a typed ceiling refusal, never for a storage fault
// while reading the granter's authority.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// TestReplaceUserRoleSet_GranterReadFaultInCommit2_IsRetrySafeFault: commit 1 removed
// a role, then commit 2's re-check of the actor's own authority (the granter's role
// read, ResolveUserPermissionAt) fails with a storage fault. The actor's authority
// did not change, so this is a fault: the answer must say retry_safe true and carry
// the fault, not claim "you no longer hold the authority" (RetryRefused) the way a
// real ceiling refusal does (TestReplaceUserRoleSet_CeilingLostBetweenCommits_NotRetrySafe).
func TestReplaceUserRoleSet_GranterReadFaultInCommit2_IsRetrySafeFault(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}

		a := w.newUser("fault-a", "project_admin")
		w.newUser("fault-b", "project_admin")
		target := w.newUser("fault-t", "project_developer")

		storeFault := errors.New("injected: granter role read failed")
		commit2Lock := sodGrantLockKey("user", target.ID)
		c := NewKeyorixCore(hooked(w.fs, &storeHooks{
			WithNamedLock: func(next storage.Storage, ctx context.Context, key string, fn func(context.Context) error) error {
				if key == commit2Lock {
					// The first read inside commit 2 is the granter's roles.assign check.
					w.fs.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError, Err: storeFault})
				}
				return next.WithNamedLock(ctx, key, fn)
			},
		}))

		err := c.SetUserRoles(ctx, a.ID, target.ID, []uint{w.viewerRole.ID}, scope, false)
		require.True(t, w.fs.Fired(), "the fault must fire on the granter's role read in commit 2")
		pe, ok := AsPartialMutationError(err)
		require.True(t, ok, "the removal committed, so the answer must say so: %v", err)
		assert.ErrorIs(t, err, storeFault, "the storage fault is reported as the cause")
		assert.NotErrorIs(t, err, ErrPermissionDenied, "a storage fault is not a refusal")
		assert.False(t, pe.RetryRefused, "a storage fault is not a ceiling refusal")
		assert.Equal(t, true, pe.Details()["retry_safe"], "the actor still holds the authority: the retry is safe")
		assert.True(t, strings.Contains(pe.ClientMessage(), "retry the same request"), pe.ClientMessage())
		assert.Empty(t, w.exactRoles(target.ID, scope), "the removal stands, the addition did not happen")
	})
}
