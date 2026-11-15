package coretests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedRouteGateGrant gives actorID a global role (roleID, which must be free)
// holding perms: the route-gate permissions core checks itself since #4161
// (internal/core/route_gate.go), so a test about the audit trail still reaches
// the write it audits. Missing permission rows are created, and the tables it
// needs are migrated if the test's world lacks them.
func seedRouteGateGrant(t *testing.T, db *gorm.DB, actorID, roleID uint, perms ...string) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.SystemMetadata{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{}))
	name := fmt.Sprintf("seeded-route-gate-%d", roleID)
	require.NoError(t, db.Create(&models.Role{ID: roleID, Name: name, NameFolded: name}).Error)
	for _, p := range perms {
		var perm models.Permission
		require.NoError(t, db.Where(models.Permission{Name: p}).
			Attrs(models.Permission{Resource: "route-gate", Action: p}).FirstOrCreate(&perm).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: roleID, PermissionID: perm.ID}).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: roleID}).Error)
}
