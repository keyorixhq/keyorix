package store

// scoped_grant_missing_scope_row_test.go — THREATMODEL-VERIFY-1, #2795 read side
// (INV-STORE-scoped-grant-needs-live-scope-row). Every role reader tested a scoped
// grant's project/environment with `deleted_at IS NULL` on a LEFT JOIN, so a grant
// whose project or environment ROW IS GONE (purged, or never there) read as live: a
// purged project's leftover grants kept authorizing at that project id. A scoped
// grant now needs its row to exist and be live. Each reader is pinned, with a live
// row as the positive control so the refusal cannot pass by refusing everything.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type missingScopeWorld struct {
	ppWorld
	perm                     *models.Permission
	userID, groupID, machine uint
	directRole, groupRole    uint
	machineRole              uint
	scope                    storage.Scope
	purge                    func()
}

// newMissingScopeWorld grants a user (directly and through a live group) and a
// machine a role holding perm at scope, where scope's project (purgeEnv=false) or
// environment (purgeEnv=true) row is removed by purge().
func newMissingScopeWorld(t *testing.T, ls *LocalStorage, purgeEnv bool) missingScopeWorld {
	t.Helper()
	ctx := context.Background()
	w := missingScopeWorld{ppWorld: ppWorld{t: t, ls: ls}}
	w.perm = w.ppWorld.perm()
	home := w.project() // the machine's own project, never purged
	w.machine = w.ppWorld.machine(home)
	w.userID = w.user()
	w.groupID = w.group()
	require.NoError(t, ls.AddUserToGroup(ctx, w.userID, w.groupID, 0))

	pid := w.project()
	w.scope = storage.Scope{ProjectID: pid}
	if purgeEnv {
		w.scope.EnvironmentID = w.env(pid)
	}
	w.directRole = w.role(false, w.perm).ID
	w.groupRole = w.role(false, w.perm).ID
	w.machineRole = w.role(false, w.perm).ID
	require.NoError(t, ls.AssignRole(ctx, w.userID, w.directRole, w.scope))
	require.NoError(t, ls.AssignRoleToGroup(ctx, w.groupID, w.groupRole, w.scope))
	require.NoError(t, ls.AssignMachineRole(ctx, w.machine, w.machineRole, w.scope))

	w.purge = func() {
		// A hard delete of the row the grants point at, as a purge leaves it: the
		// grant rows themselves stay.
		if purgeEnv {
			require.NoError(t, ls.db.Exec("DELETE FROM environments WHERE id = ?", w.scope.EnvironmentID).Error)
			return
		}
		require.NoError(t, ls.db.Exec("DELETE FROM projects WHERE id = ?", w.scope.ProjectID).Error)
	}
	return w
}

// readers returns, per reader, the role ids it reports as applying at w.scope.
func (w missingScopeWorld) readers() map[string]func() []uint {
	ctx := context.Background()
	t := w.t
	ls := w.ls
	return map[string]func() []uint{
		"GetUserRoleIDsAt": func() []uint {
			ids, err := ls.GetUserRoleIDsAt(ctx, w.userID, w.scope)
			require.NoError(t, err)
			return ids
		},
		"GetUserGroupRoleIDsAt": func() []uint {
			ids, err := ls.GetUserGroupRoleIDsAt(ctx, w.userID, w.scope)
			require.NoError(t, err)
			return ids
		},
		"GetMachineRoleIDsAt": func() []uint {
			ids, err := ls.GetMachineRoleIDsAt(ctx, w.machine, w.scope)
			require.NoError(t, err)
			return ids
		},
		"ResolveUserPermissionAt": func() []uint {
			pp, err := ls.ResolveUserPermissionAt(ctx, w.userID, w.scope, w.perm.Name)
			require.NoError(t, err)
			if !pp.HasPermission && !pp.BypassesPermissionChecks {
				return nil
			}
			return pp.RoleIDs
		},
		"ResolveMachinePermissionAt": func() []uint {
			pp, err := ls.ResolveMachinePermissionAt(ctx, w.machine, w.scope, w.perm.Name)
			require.NoError(t, err)
			if !pp.HasPermission {
				return nil
			}
			return pp.RoleIDs
		},
		"ListUserRoleGrants": func() []uint {
			grants, err := ls.ListUserRoleGrants(ctx, w.userID)
			require.NoError(t, err)
			var ids []uint
			for _, g := range grants {
				if g.ProjectID == w.scope.ProjectID && g.EnvironmentID == w.scope.EnvironmentID {
					ids = append(ids, g.RoleID)
				}
			}
			return ids
		},
	}
}

func TestScopedGrant_MissingScopeRowAuthorizesNothing(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		for _, tc := range []struct {
			name     string
			purgeEnv bool
		}{{"project row purged", false}, {"environment row purged", true}} {
			t.Run(backend+"/"+tc.name, func(t *testing.T) {
				ls, _ := newPrincipalPermStorage(t, backend)
				w := newMissingScopeWorld(t, ls, tc.purgeEnv)
				readers := w.readers()

				// Positive control: with the row live, every reader sees its grant.
				for name, read := range readers {
					require.NotEmpty(t, read(), "%s: a grant at a live scope must apply (control)", name)
				}

				w.purge()
				for name, read := range readers {
					assert.Empty(t, read(),
						"%s: a scoped grant whose %s row is gone must authorize nothing, not read as live",
						name, map[bool]string{false: "project", true: "environment"}[tc.purgeEnv])
				}
			})
		}
	}
}

// The machine value-read prefetch folds the role read into the node read: its
// subquery is GetMachineRoleIDsAt's and must refuse a grant at a scope whose
// environment row is gone in the same way.
func TestReadPathPrefetch_MissingEnvironmentRowAuthorizesNothing(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			_, perm, _ := w.gateReads(storage.NewReadPathPrefetch(ctx, w.machine, true))
			require.True(t, perm.HasPermission, "precondition: allowed while the environment row is live")

			require.NoError(t, w.ls.db.Exec("DELETE FROM environments WHERE id = ?", w.scope.EnvironmentID).Error)

			_, perm, _ = w.gateReads(storage.NewReadPathPrefetch(ctx, w.machine, true))
			assert.Empty(t, perm.RoleIDs)
			assert.False(t, perm.HasPermission, "a grant at a purged environment must authorize nothing")
		})
	}
}
