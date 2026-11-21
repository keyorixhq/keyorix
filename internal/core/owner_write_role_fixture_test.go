package core

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedOwnerWriteRoleForTest gives userID a global role holding secrets.write, for
// fixtures whose secret owner sets tags or a description or moves the secret. Since
// #4508 the owner pass alone no longer authorizes those writes in core (the REST
// gate is secrets.write with no owner pass), so an owner whose role row names no
// real role is the viewer-owner the route refuses. The grant is global (these
// fixtures seed no project rows, and role resolution requires a live project for a
// project-scoped grant); the tables role resolution reads are migrated here.
func seedOwnerWriteRoleForTest(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SystemMetadata{}))
	role := &models.Role{Name: "owner-writer-fixture"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{}
	if err := db.Where("name = ?", "secrets.write").First(perm).Error; err != nil {
		perm = &models.Permission{Name: "secrets.write", Resource: "secrets", Action: "write"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID}).Error)
}
