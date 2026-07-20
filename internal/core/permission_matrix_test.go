package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newMatrixCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.User{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seed helpers
func seedMatrixUser(t *testing.T, db *gorm.DB, id uint, username, email string) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: id, Username: username, Email: email}).Error)
}

func seedMatrixRole(t *testing.T, db *gorm.DB, id uint, name string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Role{ID: id, Name: name}).Error)
}

func seedMatrixPerm(t *testing.T, db *gorm.DB, id uint, name, resource, action string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Permission{ID: id, Name: name, Resource: resource, Action: action}).Error)
}

func seedMatrixRolePerm(t *testing.T, db *gorm.DB, roleID, permID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.RolePermission{RoleID: roleID, PermissionID: permID}).Error)
}

// TestGetPermissionMatrix_GlobalGrant — a user with a global role (project_id=0)
// yields a row with Scope="global" and no project/environment name.
func TestGetPermissionMatrix_GlobalGrant(t *testing.T) {
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 1, "alice", "alice@example.com")
	seedMatrixRole(t, db, 10, "admin")
	seedMatrixPerm(t, db, 100, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 10, 100)
	// global grant: project_id=0, environment_id=0
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 0, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	r := rows[0]
	assert.Equal(t, uint(1), r.UserID)
	assert.Equal(t, "alice", r.Username)
	assert.Equal(t, "alice@example.com", r.Email)
	assert.Equal(t, uint(10), r.RoleID)
	assert.Equal(t, "admin", r.RoleName)
	assert.Equal(t, "secrets.read", r.PermissionName)
	assert.Equal(t, "secrets", r.Resource)
	assert.Equal(t, "read", r.Action)
	assert.Equal(t, "global", r.Scope)
	assert.Zero(t, r.ProjectID)
	assert.Empty(t, r.ProjectName)
	assert.Nil(t, r.ExpiresAt)
}

// TestGetPermissionMatrix_ProjectScoped — a project-scoped grant appears with the
// project's name in the row.
func TestGetPermissionMatrix_ProjectScoped(t *testing.T) {
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 5, Name: "project-a"}).Error)
	seedMatrixUser(t, db, 2, "bob", "bob@example.com")
	seedMatrixRole(t, db, 20, "viewer")
	seedMatrixPerm(t, db, 200, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 20, 200)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 20, ProjectID: 5, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	r := rows[0]
	assert.Equal(t, "bob", r.Username)
	assert.Equal(t, "project", r.Scope)
	assert.Equal(t, uint(5), r.ProjectID)
	assert.Equal(t, "project-a", r.ProjectName)
	assert.Zero(t, r.EnvironmentID)
	assert.Nil(t, r.ExpiresAt)
}

// TestGetPermissionMatrix_FilterByProject — projectID filter excludes grants for
// other projects while including global grants (project_id=0).
func TestGetPermissionMatrix_FilterByProject(t *testing.T) {
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-alpha"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "proj-beta"}).Error)

	seedMatrixUser(t, db, 10, "carol", "carol@example.com")
	seedMatrixRole(t, db, 30, "editor")
	seedMatrixPerm(t, db, 300, "secrets.write", "secrets", "write")
	seedMatrixRolePerm(t, db, 30, 300)

	// grant in project-1
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 30, ProjectID: 1, EnvironmentID: 0}).Error)
	// grant in project-2 (should be excluded when filtering by project 1)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 30, ProjectID: 2, EnvironmentID: 0}).Error)
	// global grant (should be included even with project filter)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 30, ProjectID: 0, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 1)
	require.NoError(t, err)
	// project-1 grant + global grant = 2 rows; project-2 grant excluded
	require.Len(t, rows, 2)

	scopes := make(map[string]bool)
	for _, r := range rows {
		scopes[r.Scope] = true
		assert.NotEqual(t, uint(2), r.ProjectID, "project-2 grant must be excluded")
	}
	assert.True(t, scopes["project"], "project-scoped row expected")
	assert.True(t, scopes["global"], "global row must be included in project filter")
}

// TestGetPermissionMatrix_MultiplePermissions — a role with 2 permissions produces
// 2 rows per grant.
func TestGetPermissionMatrix_MultiplePermissions(t *testing.T) {
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 3, "dave", "dave@example.com")
	seedMatrixRole(t, db, 40, "poweruser")
	seedMatrixPerm(t, db, 400, "secrets.read", "secrets", "read")
	seedMatrixPerm(t, db, 401, "secrets.write", "secrets", "write")
	seedMatrixRolePerm(t, db, 40, 400)
	seedMatrixRolePerm(t, db, 40, 401)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 40, ProjectID: 0, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2, "2 permissions × 1 grant = 2 rows")

	permNames := map[string]bool{}
	for _, r := range rows {
		permNames[r.PermissionName] = true
		assert.Equal(t, "dave", r.Username)
		assert.Equal(t, "poweruser", r.RoleName)
		assert.Equal(t, "global", r.Scope)
	}
	assert.True(t, permNames["secrets.read"])
	assert.True(t, permNames["secrets.write"])

	// Confirm time-bound: seed a JIT grant for project_id=1 and verify ExpiresAt is set.
	// Filtering by project_id=1 also includes global grants (project_id=0), so we get
	// 4 rows total (2 from the existing global grant + 2 from the JIT project-scoped grant).
	exp := time.Now().Add(2 * time.Hour)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 40, ProjectID: 1, EnvironmentID: 0, ExpiresAt: &exp}).Error)

	rows, err = c.GetPermissionMatrix(ctx, 1)
	require.NoError(t, err)
	require.Len(t, rows, 4, "2 global rows + 2 project-scoped JIT rows")

	var timedRows []*PermissionMatrixRow
	for _, r := range rows {
		if r.ExpiresAt != nil {
			timedRows = append(timedRows, r)
		}
	}
	require.Len(t, timedRows, 2, "2 JIT rows expected")
	for _, r := range timedRows {
		assert.True(t, r.ExpiresAt.After(time.Now()))
		assert.Equal(t, "project", r.Scope)
	}
}

// TestGetPermissionMatrix_EnvScoped covers getEnvName and grantScope("environment").
func TestGetPermissionMatrix_EnvScoped(t *testing.T) {
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 7, Name: "proj-g"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 3, Name: "staging", ProjectID: 7}).Error)
	seedMatrixUser(t, db, 20, "eve", "eve@example.com")
	seedMatrixRole(t, db, 50, "dev")
	seedMatrixPerm(t, db, 500, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 50, 500)
	// environment-scoped grant
	require.NoError(t, db.Create(&models.UserRole{UserID: 20, RoleID: 50, ProjectID: 7, EnvironmentID: 3}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	r := rows[0]
	assert.Equal(t, "environment", r.Scope)
	assert.Equal(t, "staging", r.EnvironmentName)
	assert.Equal(t, "proj-g", r.ProjectName)
}

// TestGetPermissionMatrix_MissingProject covers getProjectName error path (soft-deleted project).
func TestGetPermissionMatrix_MissingProject(t *testing.T) {
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 30, "frank", "frank@example.com")
	seedMatrixRole(t, db, 60, "ops")
	seedMatrixPerm(t, db, 600, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 60, 600)
	// grant references project 999 which does not exist in the DB (soft-deleted)
	require.NoError(t, db.Create(&models.UserRole{UserID: 30, RoleID: 60, ProjectID: 999, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	// getProjectName falls back to "project-999" placeholder
	assert.Contains(t, rows[0].ProjectName, "999")
}
