package core

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// grantProjectSecretsWrite gives userID secrets.write at projectID through a fresh
// ordinary role (nothing admin-tier). Fixtures written before CORE-AUTHZ-RACE-NOV-1
// item 2 drove the bulk secret ops with an owner that held a user_roles row for a
// role that did not exist (RoleID 1, no roles table): enough for the membership
// guard, which is all the owner pass needed. The bulk ops now decide the route's
// gate per secret (enforceSecretWriteGate), so the owner holds secrets.write for
// real and each test keeps proving what it was written for. IDs from 880001 up
// keep clear of every literal a fixture uses.
func grantProjectSecretsWrite(t *testing.T, db *gorm.DB, userID, projectID uint) {
	t.Helper()
	grantSecretsWriteAt(t, db, userID, Scope{ProjectID: projectID})
}

// grantSecretsWriteAt is grantProjectSecretsWrite at an explicit scope (an
// environment-scoped grant reaches only that environment's secrets). The scope's
// project row is created if the fixture has none: a scoped grant counts only at a
// live project.
func grantSecretsWriteAt(t *testing.T, db *gorm.DB, userID uint, scope Scope) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SystemMetadata{},
		&models.Project{}, &models.Environment{}, &models.SecretACL{}, &models.ShareRecord{},
	))
	if scope.ProjectID != 0 {
		proj := &models.Project{}
		require.NoError(t, db.Where(&models.Project{ID: scope.ProjectID}).
			Attrs(&models.Project{Name: fmt.Sprintf("fixture-project-%d", scope.ProjectID)}).FirstOrCreate(proj).Error)
	}
	var n int64
	require.NoError(t, db.Model(&models.Role{}).Count(&n).Error)
	name := fmt.Sprintf("bulk-writer-%d-%d", userID, n)
	role := &models.Role{ID: 880001 + uint(n), Name: name, NameFolded: name}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{}
	require.NoError(t, db.Where(&models.Permission{Name: permSecretsWrite}).
		Attrs(&models.Permission{ID: 880001, Resource: "secrets", Action: "write"}).FirstOrCreate(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID}).Error)
}
