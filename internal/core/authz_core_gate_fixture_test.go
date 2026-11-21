package core

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// grantGateHolder seeds userID as an active account (created if absent) that holds
// perms at scope (a zero scope is global) through a fresh ordinary role: the
// smallest grant that passes a #4161 core route gate, nothing admin-tier. Fixtures
// written before #4161 drove the gated entry points with an actor that held no
// role at all, because the transport was the only gate; they call this so the test
// keeps proving what it was written for, not the gate.
func grantGateHolder(t *testing.T, db *gorm.DB, userID uint, scope Scope, perms ...string) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SystemMetadata{},
		&models.Project{}, &models.Environment{}, // the scoped role resolution joins them
		&models.SecretACL{}, &models.ShareRecord{}, // the secret-level gate reads them
	))
	ensureActiveActor(t, store.NewLocalStorage(db), userID)
	// IDs from 770001 up: fixtures written before #4161 create roles and permissions
	// with literal IDs (Role{ID: 1}, Permission{ID: 1}, an "unknown" 9001) and must
	// keep them.
	var n int64
	require.NoError(t, db.Model(&models.Role{}).Count(&n).Error)
	name := fmt.Sprintf("gate-holder-%d-%d", userID, n)
	role := &models.Role{ID: 770001 + uint(n), Name: name, NameFolded: name}
	require.NoError(t, db.Create(role).Error)
	for _, p := range perms {
		resource, action, _ := strings.Cut(p, ".")
		var np int64
		require.NoError(t, db.Model(&models.Permission{}).Count(&np).Error)
		perm := &models.Permission{}
		require.NoError(t, db.Where(&models.Permission{Name: p}).
			Attrs(&models.Permission{ID: 770001 + uint(np), Resource: resource, Action: action}).FirstOrCreate(perm).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{
		UserID: userID, RoleID: role.ID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID,
	}).Error)
}
