package core

// role_set_ceiling_read_fault_unavailable_test.go — #3938: a storage fault while the
// grant ceiling reads the actor's authority, or while the replacement reads the set it
// replaces, is the family's retryable ErrStorageReadUnavailable (503 / Unavailable),
// never a refusal and never an untyped error the transports answer 500. Nothing
// commits. The commit-2 case (removals already applied) is
// TestReplaceUserRoleSet_GranterReadFaultInCommit2_IsRetrySafeFault.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestReplaceUserRoleSet_ReadFaultBeforeCommit1_IsStorageUnavailable(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}

		for _, tc := range []struct {
			name, method string
			// self: the actor replaces their own set, removing project_admin; the
			// self pre-check (#3684) then reads the actor's grants under the lock.
			self bool
		}{
			{name: "granter authority read, pure addition", method: "ResolveUserPermissionAt"},
			{name: "the replaced set's read", method: "GetUserRoleIDsExact"},
			{name: "self replacement pre-check: actor grants", method: "ListUserRoleGrants", self: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				a := w.newUser("rf-a", "project_admin")
				w.newUser("rf-b", "project_admin") // a second admin: the last-admin guard lets a drop theirs
				target := w.newUser("rf-t", "project_developer")
				if tc.self {
					target = a
				}
				before := w.exactRoles(target.ID, scope)

				storeFault := errors.New("injected: ceiling read failed")
				w.fs.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: 1, Kind: faultstorage.KindError, Err: storeFault})
				err := NewKeyorixCore(w.fs).SetUserRoles(ctx, a.ID, target.ID, []uint{w.viewerRole.ID}, scope, false)
				require.True(t, w.fs.Fired(), "the fault must fire on %s", tc.method)
				w.fs.Arm(nil)

				require.Error(t, err)
				assert.True(t, IsStorageReadUnavailable(err), "a read fault is the retryable storage error, got %v", err)
				assert.ErrorIs(t, err, storeFault, "the cause stays reachable for the log")
				assert.NotErrorIs(t, err, ErrPermissionDenied, "a storage fault is not a ceiling refusal")
				_, partial := AsPartialMutationError(err)
				assert.False(t, partial, "nothing committed, so this is not a partial mutation")
				assert.NotContains(t, err.Error(), "injected", "the driver cause stays out of the client text")
				assert.Equal(t, before, w.exactRoles(target.ID, scope), "nothing may change")
			})
		}
	})
}
