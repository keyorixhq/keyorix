package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// unsupportedACLStorage wraps a real storage.Storage but forces GetSecretACL
// to return storage.ErrUnsupportedByBackend, simulating a backend (like
// RemoteStorage's still-unproxied ACL read path) that doesn't support
// SecretACL at all.
type unsupportedACLStorage struct {
	corestorage.Storage
}

func (unsupportedACLStorage) GetSecretACL(context.Context, uint, uint) (*models.SecretACL, error) {
	return nil, corestorage.ErrUnsupportedByBackend
}

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
		&models.MachineIdentityRole{},
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

// TestAuthorizeSecretPrincipal_UserACLGrant verifies the actor-aware entrypoint
// (used by RequireScopedSecretPermission) honors a per-secret ACL grant for a
// human user with no project role, mirroring TestAuthorizeSecret_ACLGrant.
func TestAuthorizeSecretPrincipal_UserACLGrant(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "principal-acl-only-secret")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 100, []string{"secrets.read"}))

	ok, err := c.AuthorizeSecretPrincipal(ctx, ActorTypeUser, 100, sid, "secrets.read")
	require.NoError(t, err)
	assert.True(t, ok, "user with ACL grant should be allowed via the actor-aware entrypoint")

	// No ACL grant covers write.
	ok2, err := c.AuthorizeSecretPrincipal(ctx, ActorTypeUser, 100, sid, "secrets.write")
	require.NoError(t, err)
	assert.False(t, ok2, "ACL grant covering only read must not authorize write")
}

// TestAuthorizeSecretPrincipal_MachineSkipsACL verifies that a machine identity
// principal never consults SecretACL (which is user-scoped), even when a
// SecretACL row happens to exist for a userID matching the machine's principal
// ID — machine and user IDs are disjoint spaces, but this proves the isolation
// is enforced structurally, not by accident of test data. A machine principal
// with no role grant at the secret's scope must be denied.
func TestAuthorizeSecretPrincipal_MachineSkipsACL(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "machine-secret")

	// Grant "user" 100 a SecretACL read grant on sid.
	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 100, []string{"secrets.read"}))

	// A machine principal with the SAME numeric ID (100) and no machine role
	// grant must still be denied — the ACL row belongs to a human user, not
	// this machine identity.
	ok, err := c.AuthorizeSecretPrincipal(ctx, ActorTypeMachine, 100, sid, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok, "a machine identity must never be authorized via a user-scoped SecretACL grant")
}

// TestAuthorizeSecretPrincipal_MachineGetSecretError covers
// AuthorizeSecretPrincipal's machine-actor error branch: when the secret
// itself can't be resolved (e.g. it doesn't exist), the function must
// propagate the storage error rather than falling through to
// AuthorizePrincipal with a zero-value scope.
func TestAuthorizeSecretPrincipal_MachineGetSecretError(t *testing.T) {
	ctx := context.Background()
	c, _ := newACLCore(t)

	ok, err := c.AuthorizeSecretPrincipal(ctx, ActorTypeMachine, 1, 999999, "secrets.read")
	require.Error(t, err)
	assert.False(t, ok, "an unresolvable secret must never authorize a machine principal")
}

// TestHasSecretACL_DeniesStaleGrantAfterMembershipRemoved is the #G13
// regression implementing the review's own detection_idea: remove a project
// member who holds a SecretACL grant, assert subsequent reads using that
// grant fail. The UserRole row is deleted directly (bypassing
// RemoveProjectMember's own DeleteSecretACLsByUserAndProject cleanup call)
// to isolate the NEW authorization-time guard in aclGrantsPermission from the
// pre-existing cleanup-on-removal path — proving the grant is denied even
// when cleanup didn't run (a gap in that path, a backend that doesn't
// support it, a TOCTOU window), not only when it did.
func TestHasSecretACL_DeniesStaleGrantAfterMembershipRemoved(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "offboarding-secret")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 42, []string{"secrets.read"}))
	got, err := c.HasSecretACL(ctx, 42, sid, "secrets.read")
	require.NoError(t, err)
	require.True(t, got, "sanity: the grant must be honored while the grantee is still a project member")

	// Remove user 42's project membership WITHOUT touching the SecretACL row —
	// the stale-grant scenario this check exists to close.
	require.NoError(t, db.Where("user_id = ? AND project_id = ?", 42, 1).Delete(&models.UserRole{}).Error)

	got2, err := c.HasSecretACL(ctx, 42, sid, "secrets.read")
	require.NoError(t, err)
	assert.False(t, got2, "a SecretACL grant must not authorize a user who is no longer a member of the secret's project")
}

// TestAuthorizeSecret_DeniesStaleGrantAfterMembershipRemoved is the
// AuthorizeSecret-level counterpart: a departed member's stale ACL grant
// must not fall through to authorize a read, and — since AuthorizeSecret is
// what backs the transfer-ownership route's permission gate
// (RequireScopedSecretPermission -> AuthorizeSecretPrincipal ->
// AuthorizeSecret) — this is also what closes the "transferOwnership
// satisfied by that same stale grant" half of the detection_idea: a departed
// member can no longer even reach TransferSecretOwnership via that route,
// since AuthorizeSecret(..., "secrets.write") now denies them too.
func TestAuthorizeSecret_DeniesStaleGrantAfterMembershipRemoved(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "offboarding-secret-2")

	require.NoError(t, c.GrantSecretACL(ctx, 1, sid, 55, []string{"secrets.read", "secrets.write"}))
	ok, err := c.AuthorizeSecret(ctx, 55, sid, "secrets.write")
	require.NoError(t, err)
	require.True(t, ok, "sanity: the grant must authorize secrets.write while the grantee is still a project member")

	require.NoError(t, db.Where("user_id = ? AND project_id = ?", 55, 1).Delete(&models.UserRole{}).Error)

	ok2, err := c.AuthorizeSecret(ctx, 55, sid, "secrets.write")
	require.NoError(t, err)
	assert.False(t, ok2, "a departed member's stale ACL grant must not authorize secrets.write — this is the same check gating TransferSecretOwnership's HTTP route")
}

// TestHasSecretACL_UnsupportedBackendDegradesToNoGrant verifies that a
// backend returning storage.ErrUnsupportedByBackend for GetSecretACL (e.g.
// RemoteStorage's still-unproxied read path) degrades to "no grant" rather
// than failing every secret-access check closed — mirroring HasSecretACL's
// existing GetSecretAncestors handling for the same sentinel.
func TestHasSecretACL_UnsupportedBackendDegradesToNoGrant(t *testing.T) {
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "unsupported-backend-secret")
	c.storage = unsupportedACLStorage{c.storage}

	got, err := c.HasSecretACL(ctx, 42, sid, "secrets.read")
	require.NoError(t, err, "an unsupported-backend error from GetSecretACL must not propagate as a hard failure")
	assert.False(t, got)
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
