package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRBACReconcileCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.Permission{}, &models.RolePermission{}))
	return &KeyorixCore{storage: store.NewLocalStorage(db)}, db
}

// seedOldCatalog simulates an install seeded BEFORE connect.read existed: every
// canonical permission except connect.read, with admin/system_admin/viewer roles
// granted their (pre-connect) baseline.
func seedOldCatalog(t *testing.T, c *KeyorixCore, db *gorm.DB) {
	t.Helper()
	ctx := context.Background()
	for _, def := range defaultPermissions {
		if def.Name == "connect.read" {
			continue // the "new" permission this install predates
		}
		_, err := c.storage.CreatePermission(ctx, &models.Permission{Name: def.Name, Description: def.Description, Resource: def.Resource, Action: def.Action})
		require.NoError(t, err)
	}
	for _, rdef := range defaultRoles {
		role, err := c.storage.CreateRole(ctx, &models.Role{Name: rdef.Name, Description: rdef.Description})
		require.NoError(t, err)
		for _, permName := range rdef.Permissions {
			if permName == "connect.read" {
				continue
			}
			var p models.Permission
			require.NoError(t, db.Where("name = ?", permName).First(&p).Error)
			require.NoError(t, c.storage.AssignPermissionToRole(ctx, role.ID, p.ID))
		}
	}
}

func roleHasPerm(t *testing.T, c *KeyorixCore, role, perm string) bool {
	t.Helper()
	r, err := c.storage.GetRoleByName(context.Background(), role)
	require.NoError(t, err)
	perms, err := c.storage.GetRolePermissions(context.Background(), r.ID)
	require.NoError(t, err)
	for _, p := range perms {
		if p.Name == perm {
			return true
		}
	}
	return false
}

func TestReconcileRBAC_AddsNewPermissionToBaselineRoles(t *testing.T) {
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	// Precondition: connect.read does not exist and no role holds it.
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"))

	require.NoError(t, c.ReconcileRBACPermissions(ctx))

	// connect.read now exists and is granted to the admin roles (its baseline) ...
	assert.True(t, roleHasPerm(t, c, "admin", "connect.read"))
	assert.True(t, roleHasPerm(t, c, "system_admin", "connect.read"))
	// ... but NOT to roles whose definition omits it (least privilege).
	assert.False(t, roleHasPerm(t, c, "viewer", "connect.read"))
	assert.False(t, roleHasPerm(t, c, "system_viewer", "connect.read"))
}

func TestReconcileRBAC_DoesNotClobberExistingGrants(t *testing.T) {
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	// Simulate an operator customization: REMOVE secrets.delete from the editor role.
	editor, err := c.storage.GetRoleByName(ctx, "editor")
	require.NoError(t, err)
	var del models.Permission
	require.NoError(t, db.Where("name = ?", "secrets.delete").First(&del).Error)
	require.NoError(t, c.storage.RemovePermissionFromRole(ctx, editor.ID, del.ID))
	require.False(t, roleHasPerm(t, c, "editor", "secrets.delete"))

	require.NoError(t, c.ReconcileRBACPermissions(ctx))

	// Reconcile must NOT re-add the operator-removed grant (only new permissions flow).
	assert.False(t, roleHasPerm(t, c, "editor", "secrets.delete"), "existing-permission grants are never reconciled")
}

func TestReconcileRBAC_NoopOnFreshInstall(t *testing.T) {
	c, _ := newRBACReconcileCore(t)
	// Empty catalog (pre-bootstrap): reconcile must do nothing.
	require.NoError(t, c.ReconcileRBACPermissions(context.Background()))
	perms, err := c.storage.ListPermissions(context.Background())
	require.NoError(t, err)
	assert.Empty(t, perms, "pre-bootstrap reconcile creates nothing — bootstrap owns seeding")
}

func TestReconcileRBAC_Idempotent(t *testing.T) {
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.NoError(t, c.ReconcileRBACPermissions(ctx)) // second run: nothing new

	// admin still has exactly one connect.read grant (no duplicate row).
	r, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	var n int64
	var connectID uint
	require.NoError(t, db.Model(&models.Permission{}).Select("id").Where("name = ?", "connect.read").First(&connectID).Error)
	require.NoError(t, db.Model(&models.RolePermission{}).Where("role_id = ? AND permission_id = ?", r.ID, connectID).Count(&n).Error)
	assert.Equal(t, int64(1), n, "no duplicate grant on a second reconcile")
}
