package store

// READPATH-DANGLING-ROLE-1 (#2795, read side): a role grant whose project row is
// MISSING (the project was hard-deleted or purged and the grant row was left
// behind by a race or an old purge) must not authorize. The readers LEFT JOIN
// projects so that project_id 0 (global) needs no row; before this fix a scoped
// grant with no projects row read the joined deleted_at as NULL, i.e. live.
//
// Each test plants the dangling row with raw SQL (the role tables carry no FK
// on project_id, since 0 means global) and asks every reader of that principal
// kind. Two controls keep the assertion honest: the same grant on a live project
// still authorizes, and a global grant still applies at the dangling scope.

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// purgedProject creates a project and hard-deletes its row, returning the id
// that no projects row carries any more.
func (w ppWorld) purgedProject() uint {
	w.t.Helper()
	id := w.project()
	require.NoError(w.t, w.ls.db.Exec("DELETE FROM projects WHERE id = ?", id).Error)
	var n int64
	require.NoError(w.t, w.ls.db.Table("projects").Where("id = ?", id).Count(&n).Error)
	require.Zero(w.t, n, "project %d must have no row", id)
	return id
}

func grantRoleIDs(grants []storage.UserRoleGrant, projectID uint) []uint {
	var out []uint
	for _, g := range grants {
		if g.ProjectID == projectID {
			out = append(out, g.RoleID)
		}
	}
	return out
}

func TestDanglingProjectRoleGrant_UserDoesNotHoldPermission(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorage(t, backend)
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			perm := w.perm()
			scopedRole := w.role(false, perm)
			bypassRole := w.role(true)
			globalRole := w.role(false)
			user := w.user()
			live := w.project()
			gone := w.purgedProject()

			for _, rid := range []uint{scopedRole.ID, bypassRole.ID} {
				require.NoError(t, ls.db.Exec("INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (?, ?, ?, 0)", user, rid, gone).Error)
			}
			require.NoError(t, ls.db.Exec("INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (?, ?, ?, 0)", user, scopedRole.ID, live).Error)
			require.NoError(t, ls.db.Exec("INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (?, ?, 0, 0)", user, globalRole.ID).Error)

			goneScope := storage.Scope{ProjectID: gone}
			ids, err := ls.GetUserRoleIDsAt(ctx, user, goneScope)
			require.NoError(t, err)
			assert.Equal(t, []uint{globalRole.ID}, ids, "GetUserRoleIDsAt: only the global grant applies at a purged project")

			got, err := ls.ResolveUserPermissionAt(ctx, user, goneScope, perm.Name)
			require.NoError(t, err)
			assert.Equal(t, []uint{globalRole.ID}, got.RoleIDs, "ResolveUserPermissionAt: role ids")
			assert.False(t, got.BypassesPermissionChecks, "ResolveUserPermissionAt: a dangling bypass grant must not bypass")
			assert.False(t, got.HasPermission, "ResolveUserPermissionAt: a dangling grant must not authorize")

			grants, err := ls.ListUserRoleGrants(ctx, user)
			require.NoError(t, err)
			assert.Empty(t, grantRoleIDs(grants, gone), "ListUserRoleGrants: no grant at a purged project")

			// Controls: the live-project grant and the global grant still read.
			ids, err = ls.GetUserRoleIDsAt(ctx, user, storage.Scope{ProjectID: live})
			require.NoError(t, err)
			require.ElementsMatch(t, []uint{scopedRole.ID, globalRole.ID}, ids)
			got, err = ls.ResolveUserPermissionAt(ctx, user, storage.Scope{ProjectID: live}, perm.Name)
			require.NoError(t, err)
			require.True(t, got.HasPermission, "control: the live-project grant authorizes")
			require.Equal(t, []uint{scopedRole.ID}, grantRoleIDs(grants, live))
			require.Equal(t, []uint{globalRole.ID}, grantRoleIDs(grants, 0))
		})
	}
}

func TestDanglingProjectRoleGrant_GroupDoesNotHoldPermission(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorage(t, backend)
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			perm := w.perm()
			scopedRole := w.role(false, perm)
			bypassRole := w.role(true)
			globalRole := w.role(false)
			user := w.user()
			group := w.group()
			require.NoError(t, ls.AddUserToGroup(ctx, user, group, 0))
			live := w.project()
			gone := w.purgedProject()

			for _, rid := range []uint{scopedRole.ID, bypassRole.ID} {
				require.NoError(t, ls.db.Exec("INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (?, ?, ?, 0)", group, rid, gone).Error)
			}
			require.NoError(t, ls.db.Exec("INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (?, ?, ?, 0)", group, scopedRole.ID, live).Error)
			require.NoError(t, ls.db.Exec("INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (?, ?, 0, 0)", group, globalRole.ID).Error)

			goneScope := storage.Scope{ProjectID: gone}
			ids, err := ls.GetUserGroupRoleIDsAt(ctx, user, goneScope)
			require.NoError(t, err)
			assert.Equal(t, []uint{globalRole.ID}, ids, "GetUserGroupRoleIDsAt: only the global grant applies at a purged project")

			got, err := ls.ResolveUserPermissionAt(ctx, user, goneScope, perm.Name)
			require.NoError(t, err)
			assert.Equal(t, []uint{globalRole.ID}, got.RoleIDs, "ResolveUserPermissionAt: role ids")
			assert.False(t, got.BypassesPermissionChecks, "ResolveUserPermissionAt: a dangling bypass grant must not bypass")
			assert.False(t, got.HasPermission, "ResolveUserPermissionAt: a dangling grant must not authorize")

			grants, err := ls.ListUserRoleGrants(ctx, user)
			require.NoError(t, err)
			assert.Empty(t, grantRoleIDs(grants, gone), "ListUserRoleGrants: no group grant at a purged project")

			ids, err = ls.GetUserGroupRoleIDsAt(ctx, user, storage.Scope{ProjectID: live})
			require.NoError(t, err)
			require.ElementsMatch(t, []uint{scopedRole.ID, globalRole.ID}, ids)
			got, err = ls.ResolveUserPermissionAt(ctx, user, storage.Scope{ProjectID: live}, perm.Name)
			require.NoError(t, err)
			require.True(t, got.HasPermission, "control: the live-project group grant authorizes")
			require.Equal(t, []uint{scopedRole.ID}, grantRoleIDs(grants, live))
			require.Equal(t, []uint{globalRole.ID}, grantRoleIDs(grants, 0))
		})
	}
}

func TestDanglingProjectRoleGrant_MachineDoesNotHoldPermission(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend) // the machine holds w.perm at w.scope (a live project)
			ls := w.ls
			ctx := context.Background()
			globalRole := w.role(false)
			gone := w.purgedProject()

			require.NoError(t, ls.db.Exec("INSERT INTO machine_identity_roles (machine_identity_id, role_id, project_id, environment_id) VALUES (?, ?, ?, 0)",
				w.machine, w.role(false, w.permByName()).ID, gone).Error)
			require.NoError(t, ls.db.Exec("INSERT INTO machine_identity_roles (machine_identity_id, role_id, project_id, environment_id) VALUES (?, ?, 0, 0)",
				w.machine, globalRole.ID).Error)

			goneScope := storage.Scope{ProjectID: gone}
			ids, err := ls.GetMachineRoleIDsAt(ctx, w.machine, goneScope)
			require.NoError(t, err)
			assert.Equal(t, []uint{globalRole.ID}, ids, "GetMachineRoleIDsAt: only the global grant applies at a purged project")

			got, err := ls.ResolveMachinePermissionAt(ctx, w.machine, goneScope, w.perm)
			require.NoError(t, err)
			assert.Equal(t, []uint{globalRole.ID}, got.RoleIDs, "ResolveMachinePermissionAt: role ids")
			assert.False(t, got.HasPermission, "ResolveMachinePermissionAt: a dangling grant must not authorize")

			// The node-stamp prefetch reads the machine's roles at the node's scope.
			pf := &storage.ReadPathPrefetch{MachineID: w.machine}
			_, parked, _, ok := ls.readNodeStampPrefetching(ctx, pf, w.secret.ID, &models.SecretNode{ProjectID: gone})
			require.True(t, ok)
			require.NotNil(t, parked)
			var parkedIDs []uint
			for _, r := range parked.Rows.([]principalPermissionRow) {
				parkedIDs = append(parkedIDs, r.RoleID)
			}
			assert.Equal(t, []uint{globalRole.ID}, parkedIDs, "readNodeStampPrefetching: only the global grant at a purged project")

			// Controls: the live-project grant still authorizes, on every reader.
			got, err = ls.ResolveMachinePermissionAt(ctx, w.machine, w.scope, w.perm)
			require.NoError(t, err)
			require.True(t, got.HasPermission, "control: the live-project machine grant authorizes")
			_, parked, _, ok = ls.readNodeStampPrefetching(ctx, pf, w.secret.ID, w.secret)
			require.True(t, ok)
			parkedIDs = parkedIDs[:0]
			for _, r := range parked.Rows.([]principalPermissionRow) {
				parkedIDs = append(parkedIDs, r.RoleID)
			}
			require.Len(t, parkedIDs, 2, "control: the live-project and the global grant are prefetched")
			require.True(t, slices.Contains(parkedIDs, globalRole.ID))
		})
	}
}

// permByName returns the world's permission row (w.perm is its name).
func (w prefetchWorld) permByName() *models.Permission {
	w.t.Helper()
	var p models.Permission
	require.NoError(w.t, w.ls.db.Where("name = ?", w.perm).First(&p).Error)
	return &p
}

// seedLiveProjects creates a live projects row for each id, for fixtures that
// grant at a bare project id: since #2795 a scoped grant with no projects row
// does not authorize.
func seedLiveProjects(t *testing.T, ls *LocalStorage, ids ...uint) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, ls.db.Create(&models.Project{ID: id, Name: fmt.Sprintf("live-project-%d", id)}).Error)
	}
}
