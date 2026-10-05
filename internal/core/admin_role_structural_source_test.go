// admin_role_structural_source_test.go — INV-CORE-20 (#2496).
//
// ADR-084 made `bypasses_permission_checks` THE structural marker for "this role
// bypasses permission checks", retiring name-based admin detection in
// roleSetContainsAdmin. `installAdminRoleIDSet` was ADR-084's own documented
// "Not yet done": a SECOND, separately-maintained name list
// (`super_admin`/`admin`/`system_admin`) backing every last-install-admin guard.
//
// The two definitions disagree, and the disagreement is load-bearing in both
// directions:
//
//   - A role carrying the flag whose NAME is outside the fixed list (the seeded
//     `project_admin`, or any role the one-time backfill flagged) confers full
//     install-wide authority when held at the global scope — roleSetContainsAdmin
//     is name-blind and scope-agnostic — yet the name list cannot see it. Removing
//     the install's LAST such grant was therefore completely unguarded: no
//     last-admin refusal, install stranded with nobody able to manage users,
//     roles or settings. That is the test below.
//   - The same blindness in the other direction makes the guard over-refuse: a
//     surviving flag-carrying holder named outside the list is not counted as a
//     backup admin, so a legitimate removal is refused. Safe, but wrong.
//
// `server/http/handlers/users_update_lastadmin_test.go`'s own doc comment names
// this exact divergence ("these use two different definitions of 'admin'") and
// relies on it as a test fixture — it is a known, in-tree fact, not a
// hypothetical.
package core_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newStructuralAdminDB builds a real LocalStorage-backed install whose ONLY
// global administrator holds a role that carries BypassesPermissionChecks but is
// named outside the retired installAdminRoleNames list.
func newStructuralAdminDB(t *testing.T, roleName string) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "admin.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.User{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{},
	))
	// The admin-conferring role: structurally flagged, deliberately NOT named
	// super_admin/admin/system_admin.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: roleName, NameFolded: roleName, BypassesPermissionChecks: true}).Error)
	// #2658: the last-admin guard counts only live (existing, active) holders.
	require.NoError(t, db.Create(&models.User{
		ID: 100, Username: "soleadmin", UsernameFolded: "soleadmin",
		Email: "soleadmin@example.com", EmailFolded: "soleadmin@example.com",
		IsActive: true, AccountState: "active",
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 100, RoleID: 1}).Error)
	return db
}

// TestRemoveUserRole_RefusesLastGlobalAdmin_StructuralFlagNotName drives the real
// RemoveUserRole path. Before #2496 the global-admin branch resolved its
// admin-role set by NAME, found nothing (this install seeds no
// super_admin/admin/system_admin row at all), declared the removal "not an
// admin-role removal", and fell through to the unguarded primitive — leaving the
// install with zero administrators.
func TestRemoveUserRole_RefusesLastGlobalAdmin_StructuralFlagNotName(t *testing.T) {
	t.Parallel()
	db := newStructuralAdminDB(t, "project_admin")
	c := core.NewKeyorixCore(store.NewLocalStorage(db))

	err := c.RemoveUserRole(context.Background(), 0, 100, 1, core.Scope{})

	require.Error(t, err, "removing the install's only global admin-bypass grant must be refused, "+
		"whatever the role is NAMED — the flag is the authority, not the name")
	assert.Contains(t, err.Error(), "administrator")

	var remaining int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("role_id = ?", 1).Count(&remaining).Error)
	assert.Equal(t, int64(1), remaining, "the install must never be left with zero global administrators")
}

// A custom role name (not any seeded built-in) carrying the flag is the same
// case: the one-time ADR-084 backfill snapshotted the flag onto whatever was
// named admin-tier THEN, and nothing keeps that in step with a fixed list read
// at runtime.
func TestRemoveUserRole_RefusesLastGlobalAdmin_CustomFlaggedRoleName(t *testing.T) {
	t.Parallel()
	db := newStructuralAdminDB(t, "custom_bypass_role")
	c := core.NewKeyorixCore(store.NewLocalStorage(db))

	err := c.RemoveUserRole(context.Background(), 0, 100, 1, core.Scope{})

	require.Error(t, err, "a flag-carrying role is admin-conferring regardless of its name")

	var remaining int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("role_id = ?", 1).Count(&remaining).Error)
	assert.Equal(t, int64(1), remaining, "the install must never be left with zero global administrators")
}

// The green-direction companion: the guard must still ALLOW a removal when a
// second flag-carrying holder survives, including one whose role name is also
// outside the retired list. Without this, a guard that simply refused every
// admin-role removal would pass the two tests above while being useless.
func TestRemoveUserRole_AllowsAdminRemovalWhenAnotherFlaggedHolderSurvives(t *testing.T) {
	t.Parallel()
	db := newStructuralAdminDB(t, "project_admin")
	// A second, independent flag-carrying global admin under a DIFFERENT
	// non-canonical name — invisible to the old name list, so the old guard
	// could not have counted it as a backup either.
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "custom_bypass_role", NameFolded: "custom_bypass_role", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: 101, Username: "backupadmin", UsernameFolded: "backupadmin",
		Email: "backupadmin@example.com", EmailFolded: "backupadmin@example.com",
		IsActive: true, AccountState: "active",
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 101, RoleID: 2}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, c.RemoveUserRole(context.Background(), 0, 100, 1, core.Scope{}),
		"a backup flag-carrying global admin survives — the removal must be allowed, not refused")

	var remaining int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("role_id = ?", 1).Count(&remaining).Error)
	assert.Equal(t, int64(0), remaining, "the permitted removal must actually have been performed")
}

// A role WITHOUT the flag is not admin-conferring, so removing its last holder
// must not be refused. This is the calibration case that keeps the guard from
// degenerating into "refuse every global role removal".
func TestRemoveUserRole_AllowsNonAdminRoleRemovalAtGlobalScope(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "admin.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.User{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "system_viewer", NameFolded: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: 100, Username: "plainuser", UsernameFolded: "plainuser",
		Email: "plainuser@example.com", EmailFolded: "plainuser@example.com",
		IsActive: true, AccountState: "active",
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 100, RoleID: 1}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, c.RemoveUserRole(context.Background(), 0, 100, 1, core.Scope{}),
		"system_viewer carries no admin-bypass flag — its removal is not a last-admin event")
}
