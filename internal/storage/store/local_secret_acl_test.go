// local_secret_acl_test.go — unit tests for LocalStorage SecretACL persistence.
//
// These tests exercise CreateOrUpdateSecretACL, GetSecretACL, ListSecretACLs,
// and DeleteSecretACL directly at the store layer, independent of the core
// business-logic wrappers.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// aclStoreGrantees are the user IDs the tests below grant ACLs to on project 1. Each
// is seeded as a direct project member: since #4533 CreateOrUpdateSecretACL refuses a
// grantee who is not a member of the secret's project (the membership re-check that
// closes the GrantSecretACL vs RemoveProjectMember race), so a bare user ID is no
// longer a valid grantee.
var aclStoreGrantees = []uint{10, 20, 30, 41, 42, 43, 50, 60, 70, 71, 80}

// aclStoreMember gives userID a direct, unexpired project_viewer-shaped grant at
// projectID (the role row itself is not needed: membership is defined by the grant,
// internal/core/project_membership_definition.go).
func aclStoreMember(t *testing.T, db *gorm.DB, userID, projectID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: 1, ProjectID: projectID}).Error)
}

// newACLStore returns an isolated LocalStorage backed by an in-memory SQLite
// database with the SecretACL table migrated, a seed secret inserted, and every
// aclStoreGrantees user a member of the secret's project (1).
func newACLStore(t *testing.T) (*LocalStorage, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	// user_roles, groups, user_groups and group_roles: the #4533 membership re-check
	// reads the direct grants and, when there are none, the group grants.
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretACL{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))

	// Seed one secret so the store tests don't need a FK violation guard.
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "acl-store-secret", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	for _, uid := range aclStoreGrantees {
		aclStoreMember(t, db, uid, s.ProjectID)
	}

	return NewLocalStorage(db), s.ID
}

// ── CreateOrUpdateSecretACL ────────────────────────────────────────────────────

// TestLocalACL_Create verifies that a new SecretACL row is inserted correctly.
func TestLocalACL_Create(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	acl := &models.SecretACL{
		SecretID:    secretID,
		UserID:      10,
		Permissions: `["secrets.read"]`,
		GrantedBy:   1,
	}
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, acl))
	assert.NotZero(t, acl.ID, "ID should be populated after insert")

	// Verify it is retrievable.
	got, err := ls.GetSecretACL(ctx, secretID, 10)
	require.NoError(t, err)
	assert.Equal(t, uint(10), got.UserID)
	assert.Equal(t, `["secrets.read"]`, got.Permissions)
}

// TestLocalACL_Update verifies that a second call with the same (secret, user) pair
// updates the existing row rather than inserting a duplicate.
func TestLocalACL_Update(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	acl := &models.SecretACL{
		SecretID:    secretID,
		UserID:      20,
		Permissions: `["secrets.read"]`,
		GrantedBy:   1,
	}
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, acl))

	// Second call — update permissions.
	acl2 := &models.SecretACL{
		SecretID:    secretID,
		UserID:      20,
		Permissions: `["secrets.read","secrets.write"]`,
		GrantedBy:   1,
	}
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, acl2))

	// Must still be exactly one row.
	rows, err := ls.ListSecretACLs(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, `["secrets.read","secrets.write"]`, rows[0].Permissions)
}

// ── GetSecretACL ──────────────────────────────────────────────────────────────

// TestLocalACL_GetExisting verifies GetSecretACL returns the correct row.
func TestLocalACL_GetExisting(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 30, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))

	got, err := ls.GetSecretACL(ctx, secretID, 30)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint(30), got.UserID)
	assert.Equal(t, secretID, got.SecretID)
}

// TestLocalACL_GetMissing verifies GetSecretACL returns an error for a non-existent record.
func TestLocalACL_GetMissing(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	_, err := ls.GetSecretACL(ctx, secretID, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── ListSecretACLs ────────────────────────────────────────────────────────────

// TestLocalACL_ListReturnsAll verifies ListSecretACLs returns all rows for a secret.
func TestLocalACL_ListReturnsAll(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	for _, uid := range []uint{41, 42, 43} {
		require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
			SecretID: secretID, UserID: uid, Permissions: `["secrets.read"]`, GrantedBy: 1,
		}))
	}

	rows, err := ls.ListSecretACLs(ctx, secretID)
	require.NoError(t, err)
	assert.Len(t, rows, 3)
}

// TestLocalACL_ListEmpty verifies ListSecretACLs returns an empty slice when no grants exist.
func TestLocalACL_ListEmpty(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	rows, err := ls.ListSecretACLs(ctx, secretID)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestLocalACL_ListOnlyOwnSecret verifies ListSecretACLs scopes to the requested secret.
func TestLocalACL_ListOnlyOwnSecret(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	// Insert a second secret.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretACL{}))

	// Grant on secretID; don't grant on secret 9999.
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 50, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))

	rows, err := ls.ListSecretACLs(ctx, 9999)
	require.NoError(t, err)
	assert.Empty(t, rows, "listing for a different secret must return nothing")
}

// ── DeleteSecretACL ───────────────────────────────────────────────────────────

// TestLocalACL_Delete verifies that DeleteSecretACL removes the row.
func TestLocalACL_Delete(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	acl := &models.SecretACL{
		SecretID: secretID, UserID: 60, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, acl))
	require.NotZero(t, acl.ID)

	require.NoError(t, ls.DeleteSecretACL(ctx, acl.ID))

	// Confirm deletion.
	_, err := ls.GetSecretACL(ctx, secretID, 60)
	require.Error(t, err, "row must be absent after deletion")
}

// TestLocalACL_DeleteMissing verifies that deleting a non-existent row returns an error.
func TestLocalACL_DeleteMissing(t *testing.T) {
	ls, _ := newACLStore(t)
	ctx := context.Background()

	err := ls.DeleteSecretACL(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── ListSecretACLsByUser ────────────────────────────────────────────────────────

// TestLocalACL_ListByUser verifies ListSecretACLsByUser returns every ACL row
// for a user across secrets, and none for a different user.
func TestLocalACL_ListByUser(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	second := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "acl-store-secret-2", IsSecret: true, Status: "active"}
	require.NoError(t, ls.db.Create(second).Error)

	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 70, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: second.ID, UserID: 70, Permissions: `["secrets.write"]`, GrantedBy: 1,
	}))
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 71, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))

	rows, err := ls.ListSecretACLsByUser(ctx, 70)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "both grants for user 70, across secrets, must be returned")

	rows, err = ls.ListSecretACLsByUser(ctx, 999)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// ── DeleteSecretACLsByUserAndProject ────────────────────────────────────────────

// TestLocalACL_DeleteByUserAndProject verifies that only ACL grants for the
// given user on secrets belonging to the given project are removed — a grant
// for the same user on a DIFFERENT project's secret must survive (#G53:
// offboarding a user from one project must not touch their access elsewhere).
func TestLocalACL_DeleteByUserAndProject(t *testing.T) {
	ls, secretID := newACLStore(t) // secretID belongs to project 1
	ctx := context.Background()

	otherProjectSecret := &models.SecretNode{ProjectID: 2, EnvironmentID: 1, Name: "other-project-secret", IsSecret: true, Status: "active"}
	require.NoError(t, ls.db.Create(otherProjectSecret).Error)
	aclStoreMember(t, ls.db, 80, otherProjectSecret.ProjectID) // a grantee must be a member of each project (#4533)

	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 80, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))
	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: otherProjectSecret.ID, UserID: 80, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))

	require.NoError(t, ls.DeleteSecretACLsByUserAndProject(ctx, 80, 1))

	_, err := ls.GetSecretACL(ctx, secretID, 80)
	require.Error(t, err, "the project-1 grant must be gone")

	got, err := ls.GetSecretACL(ctx, otherProjectSecret.ID, 80)
	require.NoError(t, err, "the project-2 grant for the same user must survive")
	assert.Equal(t, uint(80), got.UserID)
}

func TestLocalACL_DeleteByUserAndProject_NoMatchIsNoop(t *testing.T) {
	ls, _ := newACLStore(t)
	require.NoError(t, ls.DeleteSecretACLsByUserAndProject(context.Background(), 404, 404))
}

// TestLocalACL_RefusesSoftDeletedSecret: the single-process half of INV-STORE-21 for
// ACL grants (#2649). A grant on a soft-deleted secret is refused and leaves no row,
// because DeleteSecret's CWE-284 cascade has already run for that secret and nothing
// would ever delete the new grant before RestoreSecret reactivates it.
func TestLocalACL_RefusesSoftDeletedSecret(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Delete(&models.SecretNode{}, secretID).Error)

	err := ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 10, Permissions: `["secrets.read"]`, GrantedBy: 1,
	})
	require.Error(t, err)
	acls, lerr := ls.ListSecretACLs(ctx, secretID)
	require.NoError(t, lerr)
	assert.Empty(t, acls, "the refused grant must have been rolled back")
}

// ── #4533: the grantee must be a member of the secret's project when the grant commits ──

// TestLocalACL_RefusesNonMemberGrantee: the single-process half of #4533. A grantee
// with no live role grant at the secret's project is refused with
// storage.ErrSecretACLGranteeNotMember and the upsert leaves no row. This is what
// RemoveProjectMember's CWE-284 cascade (DeleteSecretACLsByUserAndProject) would have
// had to sweep and could not see when it committed first.
func TestLocalACL_RefusesNonMemberGrantee(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()

	err := ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 999, Permissions: `["secrets.read"]`, GrantedBy: 1,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrSecretACLGranteeNotMember)
	_, gerr := ls.GetSecretACL(ctx, secretID, 999)
	assert.True(t, storage.IsSecretACLNotFound(gerr), "the refused grant must have been rolled back: %v", gerr)
}

// TestLocalACL_RefusesGranteeWhoseOnlyGrantIsGlobal: a global (project_id = 0) role
// does not make anyone a member of any project (ADR-021), so it does not make a valid
// grantee either — the same answer core.GrantSecretACL's own pre-check gives.
func TestLocalACL_RefusesGranteeWhoseOnlyGrantIsGlobal(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()
	aclStoreMember(t, ls.db, 998, 0)

	err := ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 998, Permissions: `["secrets.read"]`, GrantedBy: 1,
	})
	assert.ErrorIs(t, err, storage.ErrSecretACLGranteeNotMember)
}

// TestLocalACL_RefusesGranteeWhoseDirectGrantExpired: an expired grant has already
// stopped authorizing (user_roles.expires_at), so its holder is not a member and the
// re-check refuses them like IsProjectMember would.
func TestLocalACL_RefusesGranteeWhoseDirectGrantExpired(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 997, RoleID: 1, ProjectID: 1, ExpiresAt: &past}).Error)

	err := ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 997, Permissions: `["secrets.read"]`, GrantedBy: 1,
	})
	assert.ErrorIs(t, err, storage.ErrSecretACLGranteeNotMember)
}

// TestLocalACL_AcceptsGroupOnlyMemberGrantee: membership through a non-deleted group
// counts (the one definition of membership includes group grants), so the re-check
// must not refuse a grantee who holds no direct grant. The control that keeps the
// re-check from being stricter than the definition it re-asks.
func TestLocalACL_AcceptsGroupOnlyMemberGrantee(t *testing.T) {
	ls, secretID := newACLStore(t)
	ctx := context.Background()
	g := &models.Group{Name: "acl-grantees", NameFolded: "acl-grantees"}
	require.NoError(t, ls.db.Create(g).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 996, GroupID: g.ID}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 1, ProjectID: 1}).Error)

	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 996, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))
	got, err := ls.GetSecretACL(ctx, secretID, 996)
	require.NoError(t, err)
	assert.Equal(t, uint(996), got.UserID)
}
