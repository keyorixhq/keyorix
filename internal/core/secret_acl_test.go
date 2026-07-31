package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newACLCore returns a KeyorixCore backed by an in-memory SQLite DB with all
// tables needed for the ACL tests already migrated.
func newACLCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretACL{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{}, &models.ShareRecord{},
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))
	// Seed project + environment.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	// Seed project membership for common test grantee IDs; GrantSecretACL checks
	// IsProjectMember before storing the ACL row. RoleID 999 is a placeholder —
	// IsProjectMember only filters on user_id + project_id, not role_id.
	for _, uid := range []uint{1, 5, 7, 42, 55, 100} {
		require.NoError(t, db.Create(&models.UserRole{UserID: uid, RoleID: 999, ProjectID: 1}).Error)
	}
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkACLSecret inserts a secret under project 1 / environment 1 and returns its ID.
func mkACLSecret(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

// TestGrantSecretACL_CreatesACLRow verifies that GrantSecretACL stores a row.
func TestGrantSecretACL_CreatesACLRow(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "stripe-api-key")

	err := c.GrantSecretACL(ctx, 99, sid, 42, []string{"secrets.read"})
	require.NoError(t, err)

	acls, err := c.ListSecretACLs(ctx, sid)
	require.NoError(t, err)
	require.Len(t, acls, 1)
	assert.Equal(t, uint(42), acls[0].UserID)
	assert.Equal(t, uint(99), acls[0].GrantedBy)
	perms := DecodeSecretACLPerms(acls[0].Permissions)
	assert.Equal(t, []string{"secrets.read"}, perms)
}

// TestGrantSecretACL_InvalidPerm verifies that invalid permissions are rejected.
func TestGrantSecretACL_InvalidPerm(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "my-secret")

	err := c.GrantSecretACL(ctx, 99, sid, 42, []string{"secrets.delete"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ACL permission")
}

// TestHasSecretACL_MatchingPerm verifies HasSecretACL returns true for matching perm.
func TestHasSecretACL_MatchingPerm(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "api-key")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 7, []string{"secrets.read"}))

	got, err := c.HasSecretACL(ctx, 7, sid, "secrets.read")
	require.NoError(t, err)
	assert.True(t, got)
}

// TestHasSecretACL_OtherPerm verifies HasSecretACL returns false for a different perm.
func TestHasSecretACL_OtherPerm(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "api-key")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 7, []string{"secrets.read"}))

	got, err := c.HasSecretACL(ctx, 7, sid, "secrets.write")
	require.NoError(t, err)
	assert.False(t, got)
}

// TestHasSecretACL_NoGrant returns false when no ACL exists.
func TestHasSecretACL_NoGrant(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "no-grant-secret")

	got, err := c.HasSecretACL(ctx, 99, sid, "secrets.read")
	require.NoError(t, err)
	assert.False(t, got)
}

// TestRevokeSecretACL_DeletesRow verifies that RevokeSecretACL removes the row.
func TestRevokeSecretACL_DeletesRow(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "to-revoke")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 5, []string{"secrets.read"}))

	acls, err := c.ListSecretACLs(ctx, sid)
	require.NoError(t, err)
	require.Len(t, acls, 1)
	aclID := acls[0].ID

	require.NoError(t, c.RevokeSecretACL(ctx, 1, sid, aclID))

	acls2, err := c.ListSecretACLs(ctx, sid)
	require.NoError(t, err)
	assert.Empty(t, acls2)
}

// TestRevokeSecretACL_WrongSecret returns an error when aclID doesn't belong to secretID.
func TestRevokeSecretACL_WrongSecret(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid1 := mkACLSecret(t, db, "secret-one")
	sid2 := mkACLSecret(t, db, "secret-two")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid1, 5, []string{"secrets.read"}))
	acls, err := c.ListSecretACLs(ctx, sid1)
	require.NoError(t, err)
	require.Len(t, acls, 1)

	// Try to revoke ACL from sid1 via sid2 — must fail.
	err = c.RevokeSecretACL(ctx, 1, sid2, acls[0].ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

// TestAuthorizeSecret_ACLGrant verifies a user with only a SecretACL (no project role)
// gets secrets.read access to that specific secret.
func TestAuthorizeSecret_ACLGrant(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "acl-only-secret")
	sid2 := mkACLSecret(t, db, "other-secret")

	// Grant user 100 read on sid only.
	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 100, []string{"secrets.read"}))

	// User 100 with ACL on sid → allowed.
	ok, err := c.AuthorizeSecret(ctx, 100, sid, "secrets.read")
	require.NoError(t, err)
	assert.True(t, ok, "user with ACL should be allowed")

	// User 100 has no ACL on sid2 and no project role → denied.
	ok2, err := c.AuthorizeSecret(ctx, 100, sid2, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok2, "user with no ACL and no role on other secret should be denied")
}

// TestAuthorizeSecret_ProjectRoleFallback verifies that a user with a project role
// (and no SecretACL) still gets access via the RBAC fallback path.
func TestAuthorizeSecret_ProjectRoleFallback(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "rbac-secret")

	// Create a project_admin role with secrets.read permission.
	role := &models.Role{Name: "project_admin", Description: "admin"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	// Assign role to user 200 at project scope (project 1).
	require.NoError(t, db.Create(&models.UserRole{UserID: 200, RoleID: role.ID, ProjectID: 1}).Error)

	// User 200 has no SecretACL but has project role → fallback grants access.
	ok, err := c.AuthorizeSecret(ctx, 200, sid, "secrets.read")
	require.NoError(t, err)
	assert.True(t, ok, "user with project role should get access via RBAC fallback")
}

// TestGrantSecretACL_Upsert verifies that a second grant on the same (secret, user)
// updates rather than inserting a duplicate.
func TestGrantSecretACL_Upsert(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "upsert-secret")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 55, []string{"secrets.read"}))
	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 55, []string{"secrets.read", "secrets.write"}))

	acls, err := c.ListSecretACLs(ctx, sid)
	require.NoError(t, err)
	// Must be exactly one row (upsert, not insert).
	require.Len(t, acls, 1)
	perms := DecodeSecretACLPerms(acls[0].Permissions)
	assert.ElementsMatch(t, []string{"secrets.read", "secrets.write"}, perms)
}
