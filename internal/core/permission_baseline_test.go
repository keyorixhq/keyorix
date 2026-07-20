package core

import (
	"context"
	"errors"
	"testing"

	stg "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newBaselineCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store}
}

// userFilterPageSize matches any UserFilter with the given PageSize (other fields may be zero).
func userFilterPageSize(n int) interface{} {
	return mock.MatchedBy(func(f *stg.UserFilter) bool {
		return f != nil && f.PageSize == n
	})
}

func TestGetPermissionBaseline_Empty(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Empty(t, baseline.Rows)
}

func TestGetPermissionBaseline_DirectGrant_GlobalScope(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 10, Username: "alice", Email: "alice@example.com"}
	grant := &models.UserRole{UserID: 10, RoleID: 5, ProjectID: 0}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)
	store.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "Admin"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(5)).
		Return([]*models.Permission{{Name: "secrets.read"}, {Name: "secrets.write"}}, nil)
	store.On("GetUserGroups", mock.Anything, uint(10)).Return([]*models.Group{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Len(t, baseline.Rows, 2)

	row := baseline.Rows[0]
	assert.Equal(t, uint(10), row.UserID)
	assert.Equal(t, "alice", row.Username)
	assert.Equal(t, "alice@example.com", row.Email)
	assert.Equal(t, "Admin", row.RoleName)
	assert.Equal(t, "global", row.Scope)
}

func TestGetPermissionBaseline_DirectGrant_ProjectScope(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 11, Username: "bob", Email: "bob@example.com"}
	grant := &models.UserRole{UserID: 11, RoleID: 7, ProjectID: 3}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)
	store.On("GetRole", mock.Anything, uint(7)).Return(&models.Role{ID: 7, Name: "Viewer"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(7)).
		Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	store.On("GetUserGroups", mock.Anything, uint(11)).Return([]*models.Group{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 1)
	assert.Equal(t, "project:3", baseline.Rows[0].Scope)
}

func TestGetPermissionBaseline_GroupInheritedGrant(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 12, Username: "carol", Email: "carol@example.com"}
	group := &models.Group{ID: 20}
	role := &models.Role{ID: 9, Name: "Operator"}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("GetUserGroups", mock.Anything, uint(12)).Return([]*models.Group{group}, nil)
	store.On("GetGroupRoles", mock.Anything, uint(20)).Return([]*models.Role{role}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(9)).
		Return([]*models.Permission{{Name: "audit.read"}}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 1)
	row := baseline.Rows[0]
	assert.Equal(t, "carol", row.Username)
	assert.Equal(t, "Operator", row.RoleName)
	assert.Equal(t, "global", row.Scope)
	assert.Equal(t, "audit.read", row.Permission)
}

func TestGetPermissionBaseline_RolePermissionsCached(t *testing.T) {
	// Two grants with the same roleID should only call GetRolePermissions once.
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	u1 := &models.User{ID: 13, Username: "dave", Email: "dave@example.com"}
	u2 := &models.User{ID: 14, Username: "eve", Email: "eve@example.com"}
	grant1 := &models.UserRole{UserID: 13, RoleID: 5, ProjectID: 0}
	grant2 := &models.UserRole{UserID: 14, RoleID: 5, ProjectID: 0}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{u1, u2}, int64(2), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant1, grant2}, nil)
	store.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "Admin"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(5)).
		Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	store.On("GetUserGroups", mock.Anything, uint(13)).Return([]*models.Group{}, nil)
	store.On("GetUserGroups", mock.Anything, uint(14)).Return([]*models.Group{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Len(t, baseline.Rows, 2)
	// GetRolePermissions should have been called exactly once for the cached role.
	store.AssertNumberOfCalls(t, "GetRolePermissions", 1)
}

func TestGetPermissionBaseline_SkipsGrantsForMissingUsers(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	// Grant references userID 99 which is not in the users list (soft-deleted).
	grant := &models.UserRole{UserID: 99, RoleID: 5, ProjectID: 0}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Empty(t, baseline.Rows)
}

func TestGetPermissionBaseline_ListUsersError(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return(nil, int64(0), errors.New("db error"))

	_, err := c.GetPermissionBaseline(ctx)
	require.Error(t, err)
}

func TestGetPermissionBaseline_ListGrantsError(t *testing.T) {
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return(nil, errors.New("grants error"))

	_, err := c.GetPermissionBaseline(ctx)
	require.Error(t, err)
}

func TestScopeLabel(t *testing.T) {
	assert.Equal(t, "global", scopeLabel(0))
	assert.Equal(t, "project:7", scopeLabel(7))
	assert.Equal(t, "project:100", scopeLabel(100))
}
