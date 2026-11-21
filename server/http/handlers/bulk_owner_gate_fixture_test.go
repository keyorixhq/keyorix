package handlers

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// grantProjectSecretsWrite gives userID secrets.write at projectID through a fresh
// ordinary role, creating the project row when the fixture has none (a scoped grant
// counts only at a live project). The bulk secret handlers' core entry points decide
// the route's gate per secret since CORE-AUTHZ-RACE-NOV-1 item 2, so an owner
// fixture that bypasses the router holds that permission for real; the tests keep
// proving what they were written for. IDs from 880001 up keep clear of every
// literal a fixture uses.
func grantProjectSecretsWrite(t *testing.T, db *gorm.DB, userID, projectID uint) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SystemMetadata{},
		&models.Project{}, &models.Environment{}, &models.SecretACL{}, &models.ShareRecord{},
	))
	proj := &models.Project{}
	require.NoError(t, db.Where(&models.Project{ID: projectID}).
		Attrs(&models.Project{Name: fmt.Sprintf("fixture-project-%d", projectID)}).FirstOrCreate(proj).Error)
	var n int64
	require.NoError(t, db.Model(&models.Role{}).Count(&n).Error)
	name := fmt.Sprintf("bulk-writer-%d-%d", userID, n)
	role := &models.Role{ID: 880001 + uint(n), Name: name, NameFolded: name}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{}
	require.NoError(t, db.Where(&models.Permission{Name: "secrets.write"}).
		Attrs(&models.Permission{ID: 880001, Resource: "secrets", Action: "write"}).FirstOrCreate(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID, ProjectID: projectID}).Error)
}
