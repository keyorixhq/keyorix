// authz_gate_fixture_test.go — #4161: core now decides the route gates itself
// (internal/core/authz_core_gate.go), so a handler test that drives a handler
// directly, without the router, has to give its acting user the permissions the
// route gate would have required; a user with no roles is refused by core exactly
// as the router refused it before.
package handlers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// grantGlobalPermissions gives userID a fresh role carrying exactly perms at the
// global scope, creating the permission rows and the RBAC tables where the
// fixture never migrated them. It never touches other users' grants.
func grantGlobalPermissions(t *testing.T, cs *core.KeyorixCore, userID uint, perms ...string) {
	t.Helper()
	ls, ok := cs.Storage().(*store.LocalStorage)
	require.True(t, ok, "grantGlobalPermissions needs a LocalStorage-backed core")
	db := ls.DB()
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))
	ensureActiveActorUser(t, cs.Storage(), userID)
	ctx := context.Background()
	name := fmt.Sprintf("gate-fixture-%d-%d", userID, len(perms))
	role := &models.Role{Name: name, NameFolded: name, Description: "route-gate permissions for a handler test"}
	require.NoError(t, db.Where(models.Role{Name: name}).FirstOrCreate(role).Error)
	for _, p := range perms {
		perm := &models.Permission{Name: p}
		require.NoError(t, db.Where(models.Permission{Name: p}).FirstOrCreate(perm).Error)
		require.NoError(t, db.Where(models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).
			FirstOrCreate(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}
	require.NoError(t, db.Where(models.UserRole{UserID: userID, RoleID: role.ID, ProjectID: 0}).
		FirstOrCreate(&models.UserRole{UserID: userID, RoleID: role.ID}).Error)
	_ = ctx
}
