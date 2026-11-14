package core

// GRPC-OUTAGE-TAILS-1 item 6 (#3938): an actor replacing their OWN role set. Commit 1
// removes a role; commit 2's re-check of the actor's ceiling then fails with a storage
// fault. That is a fault, not "you no longer hold the authority": the answer is a
// PartialMutationError that is retry-safe, states what commit 1 did, and carries the
// fault; the retry (fault gone) completes the replacement. A REAL ceiling refusal in
// commit 2 stays retry_safe false (TestReplaceUserRoleSet_CeilingLostBetweenCommits_NotRetrySafe).
// Every storage read the commit-2 check makes is faulted in turn. SQLite and PostgreSQL.

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

func TestReplaceUserRoleSet_SelfReplaceCommit2CeilingFault_IsRetrySafe(t *testing.T) {
	for _, method := range []string{"ResolveUserPermissionAt", "GetRolePermissions"} {
		t.Run(method, func(t *testing.T) {
			smaBackends(t, func(t *testing.T, sw *smaWorld) {
				w := newSATWorld(t, sw.f)
				ctx := context.Background()
				scope := Scope{ProjectID: w.f.projectID}
				st := w.f.setup.Storage()
				admin, err := st.GetRoleByName(ctx, "project_admin")
				require.NoError(t, err)

				// P holds project_admin and project_developer; a second admin keeps the
				// last-admin guard out of play. P replaces their own set with
				// {project_admin, project_viewer}: commit 1 removes developer, commit 2
				// adds viewer, judged on the authority P keeps through project_admin.
				p := w.newUser("self-f", "project_admin")
				w.newUser("self-f2", "project_admin")
				require.NoError(t, st.AssignRole(ctx, p.ID, w.devRole.ID, scope))
				want := []uint{admin.ID, w.viewerRole.ID}

				storeFault := errors.New("injected: ceiling read failed in commit 2")
				commit2Lock := sodGrantLockKey("user", p.ID)
				armed := false // the fault hits the first commit 2 only, not the retry's
				c := NewKeyorixCore(hooked(w.fs, &storeHooks{
					WithNamedLock: func(next storage.Storage, ctx context.Context, key string, fn func(context.Context) error) error {
						if key == commit2Lock && !armed {
							armed = true
							w.fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: storeFault})
						}
						return next.WithNamedLock(ctx, key, fn)
					},
				}))

				err = c.SetUserRoles(ctx, p.ID, p.ID, want, scope, false)
				require.True(t, w.fs.Fired(), "the fault must fire on %s inside commit 2", method)
				w.fs.Arm(nil)
				pe, ok := AsPartialMutationError(err)
				require.True(t, ok, "commit 1 removed a role, so the answer must say so: %v", err)
				assert.ErrorIs(t, err, storeFault, "the storage fault is the reported cause")
				assert.NotErrorIs(t, err, ErrPermissionDenied, "a storage fault is not a refusal")
				assert.False(t, pe.RetryRefused, "the actor's authority did not change")
				assert.Equal(t, true, pe.Details()["retry_safe"], "the retry is safe")
				assert.Contains(t, pe.Applied, "removal of role(s)", "the answer states what commit 1 did")
				assert.True(t, strings.Contains(pe.ClientMessage(), "retry the same request"), pe.ClientMessage())

				// Effect: the removal stands, the addition did not happen.
				assert.Equal(t, []uint{admin.ID}, w.exactRoles(p.ID, scope))

				// And the retry the answer promised completes the replacement.
				require.NoError(t, c.SetUserRoles(ctx, p.ID, p.ID, want, scope, false), "the retry must succeed once the fault clears")
				assert.Equal(t, sortedIDs(want...), w.exactRoles(p.ID, scope))
			})
		})
	}
}
