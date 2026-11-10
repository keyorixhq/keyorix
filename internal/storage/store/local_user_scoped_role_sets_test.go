package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func sortedRoleSets(in map[storage.Scope][]uint) map[storage.Scope][]uint {
	out := make(map[storage.Scope][]uint, len(in))
	for s, ids := range in {
		out[s] = slices.Sorted(slices.Values(ids))
	}
	return out
}

// TestGetUserScopedRoleSets_EquivalentToThePerStatementReads (#4025): in a
// quiet world, the one-statement read answers exactly what GetUserRoleScopes
// followed by GetUserRoleIDsAt ∪ GetUserGroupRoleIDsAt per scope answers, for
// direct and group grants at every scope shape the readers filter on.
func TestGetUserScopedRoleSets_EquivalentToThePerStatementReads(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, reopen := newPrincipalPermStorage(t, backend)
			classic := reopen()
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			rA, rB, rC := w.role(false, w.perm()), w.role(true), w.role(false, w.perm())
			p1, p2, pDel, pGone := w.project(), w.project(), w.project(), w.project()
			e1, eDel := w.env(p1), w.env(p1)
			past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

			gGlobal, gP1, gDel, gExp := w.group(), w.group(), w.group(), w.group()
			require.NoError(t, ls.AssignRoleToGroup(ctx, gGlobal, rA.ID, storage.Scope{}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gGlobal, rC.ID, storage.Scope{ProjectID: p2}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gP1, rB.ID, storage.Scope{ProjectID: p1}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gP1, rC.ID, storage.Scope{ProjectID: p1, EnvironmentID: e1}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gDel, rB.ID, storage.Scope{}))
			require.NoError(t, ls.AssignRoleToGroupWithExpiry(ctx, gExp, rB.ID, storage.Scope{ProjectID: p1}, past))

			var users []uint
			u := func(grant func(id uint)) {
				id := w.user()
				grant(id)
				users = append(users, id)
			}
			u(func(id uint) {})
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{})) })
			u(func(id uint) {
				require.NoError(t, ls.AssignRole(ctx, id, rA.ID, storage.Scope{}))
				require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{ProjectID: p1}))
				require.NoError(t, ls.AssignRole(ctx, id, rC.ID, storage.Scope{ProjectID: p1, EnvironmentID: e1}))
			})
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{ProjectID: pDel})) })
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{ProjectID: pGone})) })
			u(func(id uint) {
				require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{ProjectID: p1, EnvironmentID: eDel}))
			})
			u(func(id uint) {
				require.NoError(t, ls.AssignRoleWithExpiry(ctx, id, rB.ID, storage.Scope{}, past))
				require.NoError(t, ls.AssignRoleWithExpiry(ctx, id, rA.ID, storage.Scope{ProjectID: p2}, future))
			})
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gGlobal, 0)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gP1, 0)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gP1, p2)) }) // membership elsewhere
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gP1, p1)) })
			u(func(id uint) {
				require.NoError(t, ls.AddUserToGroup(ctx, id, gP1, p1))
				require.NoError(t, ls.AddUserToGroup(ctx, id, gP1, p2))
				require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{ProjectID: p1})) // same role both ways
			})
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gDel, 0)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gExp, 0)) })

			require.NoError(t, ls.DeleteGroup(ctx, gDel))
			require.NoError(t, ls.db.Delete(&models.Project{ID: pDel}).Error)
			require.NoError(t, ls.db.Delete(&models.Environment{ID: eDel}).Error)
			require.NoError(t, ls.db.Unscoped().Delete(&models.Project{ID: pGone}).Error) // purged: no row at all

			for _, id := range users {
				msg := fmt.Sprintf("user %d", id)
				want, err := storage.ComposeUserScopedRoleSets(ctx, classic, id)
				require.NoError(t, err, msg)
				got, err := ls.GetUserScopedRoleSets(ctx, id)
				require.NoError(t, err, msg)
				require.Equal(t, sortedRoleSets(want), sortedRoleSets(got), msg)
			}
		})
	}
}

// One statement is the whole point: two would be two moments again.
func TestGetUserScopedRoleSets_IsOneStatement(t *testing.T) {
	ls, _ := newPrincipalPermStorage(t, "sqlite")
	w := ppWorld{t: t, ls: ls}
	ctx := context.Background()
	id, g, p := w.user(), w.group(), w.project()
	r := w.role(true)
	require.NoError(t, ls.AssignRole(ctx, id, r.ID, storage.Scope{ProjectID: p}))
	require.NoError(t, ls.AssignRoleToGroup(ctx, g, r.ID, storage.Scope{}))
	require.NoError(t, ls.AddUserToGroup(ctx, id, g, 0))

	c := ppCountStatements(t, ls.db)
	c.mu.Lock()
	c.on = true
	c.mu.Unlock()
	got, err := ls.GetUserScopedRoleSets(ctx, id)
	require.NoError(t, err)
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Len(t, c.stmts, 1, "statements: %q", c.stmts)
	require.Len(t, got, 2)
}
