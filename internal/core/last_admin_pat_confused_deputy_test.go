package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestGuardLastAdminDeactivation_NotFooledByActingCallersPATRestriction is the
// regression for the 2026-09-07 ADR-conformance review's HIGH finding:
// guardLastAdminDeactivation asked IsGlobalAdmin(ctx, targetID) whether the
// TARGET is the last admin, but IsGlobalAdmin's PAT short-circuit
// (`patRestrictionFromContext(ctx) != nil { return false, nil }`) answers a
// different question -- "should the ACTOR on this ctx be treated as an
// unrestricted admin" -- and fires on the ACTOR's own restriction regardless
// of which targetID was asked about. An admin authenticating via their own,
// ordinary, legitimately-scoped PAT could therefore suspend/deactivate the
// install's last remaining global admin with this guard silently no-op'ing.
func TestGuardLastAdminDeactivation_NotFooledByActingCallersPATRestriction(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	setup := func(t *testing.T) (*KeyorixCore, *gorm.DB) {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
			&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Session{},
			&models.PersonalAccessToken{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}))
		ls := store.NewLocalStorage(db)
		return NewKeyorixCore(ls), db
	}

	t.Run("acting admin's own scoped PAT must not blind the guard to the target being the last admin", func(t *testing.T) {
		c, db := setup(t)

		// User 1 is the install's sole global admin.
		require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}).Error)
		require.NoError(t, db.Create(&models.User{ID: 1, Username: "lastadmin", IsActive: true, AccountState: AccountActive}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0, EnvironmentID: 0}).Error)

		// User 2 is the acting caller -- authenticated via their own, ordinary,
		// least-privilege scoped PAT (ADR-042). This is not an attack: any admin
		// who routinely uses a scoped PAT for automation would carry this ctx.
		require.NoError(t, db.Create(&models.User{ID: 2, Username: "actingadmin", IsActive: true, AccountState: AccountActive}).Error)
		ctx := WithPATRestriction(context.Background(), &PATRestriction{Permissions: []string{"users.write"}})

		err := c.SuspendUser(ctx, 2, 1)
		require.Error(t, err, "must refuse to suspend the install's last global admin, regardless of the acting caller's own PAT restriction")
		assert.Contains(t, err.Error(), "last install administrator")

		var target models.User
		require.NoError(t, db.First(&target, 1).Error)
		assert.NotEqual(t, AccountSuspended, NormalizeAccountState(target.AccountState),
			"the last admin must not actually be suspended when the guard correctly refuses")
	})

	t.Run("positive control: a genuine second admin still permits the suspend, PAT-restricted ctx included", func(t *testing.T) {
		c, db := setup(t)

		require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}).Error)
		require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin-one", IsActive: true, AccountState: AccountActive}).Error)
		require.NoError(t, db.Create(&models.User{ID: 3, Username: "admin-two", IsActive: true, AccountState: AccountActive}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0, EnvironmentID: 0}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 1, ProjectID: 0, EnvironmentID: 0}).Error)

		require.NoError(t, db.Create(&models.User{ID: 2, Username: "actingadmin", IsActive: true, AccountState: AccountActive}).Error)
		ctx := WithPATRestriction(context.Background(), &PATRestriction{Permissions: []string{"users.write"}})

		require.NoError(t, c.SuspendUser(ctx, 2, 1),
			"a second live admin exists, so the guard must still permit this suspend")
	})

	t.Run("positive control: an ordinary (non-admin) target is unaffected by the guard", func(t *testing.T) {
		c, db := setup(t)

		require.NoError(t, db.Create(&models.User{ID: 4, Username: "regularuser", IsActive: true, AccountState: AccountActive}).Error)
		require.NoError(t, db.Create(&models.User{ID: 2, Username: "actingadmin", IsActive: true, AccountState: AccountActive}).Error)
		ctx := WithPATRestriction(context.Background(), &PATRestriction{Permissions: []string{"users.write"}})

		require.NoError(t, c.SuspendUser(ctx, 2, 4))
	})
}

// TestSuspendInactiveUsers_NotFooledByCallersPATRestriction is the second
// confirmed instance of the same confused-deputy shape, found by the sweep
// this fix's review required: SuspendInactiveUsers's "skip global admins"
// check (internal/core/inactivity_suspend.go) is reachable from a live HTTP
// endpoint (AdminJobsHandler.SuspendInactiveUsers) carrying the triggering
// admin's own r.Context() -- including any PAT restriction on it. Before the
// fix, an admin who triggers this sweep via their own scoped PAT would see
// EVERY inactive global admin wrongly suspended instead of skipped, because
// IsGlobalAdmin's short-circuit fires on the CALLER's restriction, not the
// per-iteration target user's actual role.
func TestSuspendInactiveUsers_NotFooledByCallersPATRestriction(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Session{},
		&models.PersonalAccessToken{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}))
	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)

	staleTime := c.now().AddDate(0, 0, -90)

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "inactive-admin", IsActive: true, AccountState: AccountActive,
		LastLoginAt: &staleTime,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0, EnvironmentID: 0}).Error)

	// The triggering caller's ctx carries a scoped PAT restriction, exactly as
	// an admin invoking this sweep via automation with their own least-privilege
	// token would.
	ctx := WithPATRestriction(context.Background(), &PATRestriction{Permissions: []string{"users.write"}})

	result, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 30, DryRun: false})
	require.NoError(t, err)

	assert.NotContains(t, result.Suspended, uint(1),
		"the sweep must skip a genuine global admin regardless of the triggering caller's own PAT restriction")
	assert.Equal(t, 1, result.Skipped, "the admin must be counted as skipped, not silently suspended")

	var target models.User
	require.NoError(t, db.First(&target, 1).Error)
	assert.NotEqual(t, AccountSuspended, NormalizeAccountState(target.AccountState))
}
