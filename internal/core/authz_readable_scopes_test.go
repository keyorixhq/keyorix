// authz_readable_scopes_test.go — unit tests for GetReadableScopes.
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userRoleScopesStub overrides GetUserRoleScopes to return a fixed slice.
type userRoleScopesStub struct {
	corestorage.Storage
	scopes []corestorage.Scope
	err    error
}

func (s *userRoleScopesStub) GetUserRoleScopes(_ context.Context, _ uint) ([]corestorage.Scope, error) {
	return s.scopes, s.err
}

// TestGetReadableScopes_StorageError verifies that a GetUserRoleScopes error is
// propagated unchanged.
func TestGetReadableScopes_StorageError(t *testing.T) {
	ctx := context.Background()
	c, _ := newACLCore(t)
	wantErr := errors.New("scopes db failure")
	c2 := newACLCoreWithStorage(c, &userRoleScopesStub{Storage: c.storage, err: wantErr})
	_, err := c2.GetReadableScopes(ctx, 1, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// TestGetReadableScopes_GlobalScopeSkipped verifies that scopes with ProjectID==0
// (global) are silently skipped; the result is empty even though a scope was
// returned by storage.
func TestGetReadableScopes_GlobalScopeSkipped(t *testing.T) {
	ctx := context.Background()
	c, _ := newACLCore(t)
	stub := &userRoleScopesStub{
		Storage: c.storage,
		scopes:  []corestorage.Scope{{ProjectID: 0, EnvironmentID: 0}},
	}
	c2 := newACLCoreWithStorage(c, stub)
	scopes, err := c2.GetReadableScopes(ctx, 1, "secrets.read")
	require.NoError(t, err)
	assert.Empty(t, scopes)
}

// TestGetReadableScopes_AuthorizeError verifies that a scope where Authorize
// returns an error is silently skipped (fail-closed).  The stub provides a
// non-zero-project scope; the real storage (DB) is then closed so that the
// Authorize call fails with a DB error, triggering the aerr != nil continue.
func TestGetReadableScopes_AuthorizeError(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	stub := &userRoleScopesStub{
		Storage: c.storage,
		scopes:  []corestorage.Scope{{ProjectID: 1, EnvironmentID: 0}},
	}
	c2 := newACLCoreWithStorage(c, stub)

	// Close the DB so that Authorize's storage calls (GetUserRoles, etc.) fail.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	scopes, err := c2.GetReadableScopes(ctx, 1, "secrets.read")
	require.NoError(t, err) // GetReadableScopes itself doesn't propagate Authorize errors
	assert.Empty(t, scopes)
}

// TestGetReadableScopes_AuthorizeFalse verifies that a scope where Authorize
// returns (false, nil) is not included in the result.
func TestGetReadableScopes_AuthorizeFalse(t *testing.T) {
	ctx := context.Background()
	c, _ := newACLCore(t)
	// User 99 has no role grants in the DB → Authorize returns (false, nil).
	stub := &userRoleScopesStub{
		Storage: c.storage,
		scopes:  []corestorage.Scope{{ProjectID: 1, EnvironmentID: 0}},
	}
	c2 := newACLCoreWithStorage(c, stub)
	scopes, err := c2.GetReadableScopes(ctx, 99, "secrets.read")
	require.NoError(t, err)
	assert.Empty(t, scopes)
}

// TestGetReadableScopes_AuthorizeTrue verifies that a scope where the user has
// the required permission is included in the result.
func TestGetReadableScopes_AuthorizeTrue(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)

	// Seed a project-scoped secrets.read role for user 88.
	role := &models.Role{Name: "readable_scope_role"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 88, RoleID: role.ID, ProjectID: 1}).Error)

	stub := &userRoleScopesStub{
		Storage: c.storage,
		scopes:  []corestorage.Scope{{ProjectID: 1, EnvironmentID: 0}},
	}
	c2 := newACLCoreWithStorage(c, stub)
	scopes, err := c2.GetReadableScopes(ctx, 88, "secrets.read")
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	assert.Equal(t, uint(1), scopes[0].ProjectID)
}
