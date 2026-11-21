package coretests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedGroupRouteGate gives actorID users.read and roles.assign at the GLOBAL scope
// through a fresh ordinary role (nothing admin-tier): the /groups routes' gate,
// which core decides itself since #4161 (RestoreGroup, AssignRoleToGroup,
// AddUserToGroup). Fixtures written before that drove those entry points with an
// actor that held no role at all; they call this so each test keeps proving what
// it was written for. IDs from 990001 up keep clear of every literal a fixture uses.
func seedGroupRouteGate(t *testing.T, db *gorm.DB, actorID uint) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SystemMetadata{},
		&models.Project{}, &models.Environment{},
	))
	var n int64
	require.NoError(t, db.Model(&models.Role{}).Count(&n).Error)
	name := fmt.Sprintf("group-route-gate-%d-%d", actorID, n)
	role := &models.Role{ID: 990001 + uint(n), Name: name, NameFolded: name}
	require.NoError(t, db.Create(role).Error)
	for i, p := range []string{"users.read", "roles.assign"} {
		resource, action, _ := strings.Cut(p, ".")
		perm := &models.Permission{}
		require.NoError(t, db.Where(&models.Permission{Name: p}).
			Attrs(&models.Permission{ID: 990001 + uint(i), Resource: resource, Action: action}).FirstOrCreate(perm).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: role.ID}).Error)
}
