package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSCIMGuardCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestUpdateSCIMUser_RejectsEmailCollision(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive}).Error)

	adminEmail := "admin@x.io"
	_, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &adminEmail, nil)
	require.Error(t, err, "SCIM must not overwrite user 2's email to collide with the admin's")
	assert.Contains(t, err.Error(), "already in use")
}

func TestUpdateSCIMUser_RefusesLastAdminDeactivation(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error) // global admin

	no := false
	_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last install administrator")
}

func TestUpdateSCIMUser_AllowsAdminDeactivationWhenAnotherExists(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)

	no := false
	off, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.NoError(t, err, "deactivating one of two admins is allowed")
	assert.False(t, off.IsActive)
}

func TestPatchSCIMGroup_RefusesAddingMemberToAdminGroup(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error) // group confers admin

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{2}, nil)
	require.Error(t, err, "SCIM must not add a member to an admin-bearing group")
	assert.Contains(t, err.Error(), "administrative roles")
}

// TestUpdateSCIMUser_FailsClosedOnTransientEmailLookupError is the (#336) regression:
// GetUserByEmail returns a non-nil error BOTH when the email is genuinely unused AND on
// a real DB failure. The previous `eerr == nil && existing != nil && ...` guard treated
// any error identically to "no collision", silently skipping the uniqueness check on a
// transient error — reintroducing the exact vulnerability the check exists to prevent,
// on the same failure mode the sibling create-path fix (FindSCIMUser) is deliberately
// hardened against. Simulates a genuine storage failure (not the "user not found"
// sentinel text) via MockStorage and asserts the update is refused, not silently applied.
func TestUpdateSCIMUser_FailsClosedOnTransientEmailLookupError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	target := &models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive}
	ms.On("GetUser", ctx, uint(2)).Return(target, nil)
	// A genuine transient failure — NOT the "user not found" sentinel text — must fail
	// the whole update closed, not be treated as "email is unused".
	ms.On("GetUserByEmail", ctx, "new@x.io").Return(nil, errors.New("connection refused"))

	newEmail := "new@x.io"
	_, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &newEmail, nil)
	require.Error(t, err, "a transient email-lookup failure must refuse the update, not silently apply it")
	assert.NotContains(t, err.Error(), "already in use",
		"this is a lookup failure, not a collision — the error must say so, not misreport a collision")

	// The write must never have been attempted.
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// TestUpdateSCIMUser_ProceedsWhenEmailGenuinelyUnused confirms the #336 fix didn't turn
// the guard into an unconditional refusal: the ordinary "email not found" case (the
// sentinel GetUserByEmail actually returns for a genuinely-unused email) must still let
// the update proceed.
func TestUpdateSCIMUser_ProceedsWhenEmailGenuinelyUnused(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive}).Error)

	newEmail := "unused@x.io"
	updated, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &newEmail, nil)
	require.NoError(t, err)
	assert.Equal(t, "unused@x.io", updated.Email)
}

// TestGuardLastAdminDeactivation_FailsClosedOnIsGlobalAdminError is the (#337)
// regression: guardLastAdminDeactivation previously treated an IsGlobalAdmin lookup
// error identically to "confirmed not an admin" (`if err != nil || !isAdmin { return
// nil }`), silently permitting a SCIM deactivate/deprovision of the sole install admin
// on exactly the failure mode (a DB hiccup during this one check) the guard exists to
// protect against. Simulates a genuine storage failure underneath IsGlobalAdmin via
// MockStorage and asserts both call sites — UpdateSCIMUser(active:false) and
// DeprovisionSCIMUser — now refuse the operation instead of silently permitting it.
func TestGuardLastAdminDeactivation_FailsClosedOnIsGlobalAdminError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dbErr := errors.New("connection pool exhausted")

	t.Run("UpdateSCIMUser deactivate", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ctx := context.Background()
		target := &models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}
		ms.On("GetUser", ctx, uint(1)).Return(target, nil)
		ms.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return(nil, dbErr)

		no := false
		_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
		require.Error(t, err, "an IsGlobalAdmin lookup failure must refuse the deactivation, not silently permit it")
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("DeprovisionSCIMUser", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ctx := context.Background()
		target := &models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}
		ms.On("GetUser", ctx, uint(1)).Return(target, nil)
		ms.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return(nil, dbErr)

		err := c.DeprovisionSCIMUser(ctx, 9, 1)
		require.Error(t, err, "an IsGlobalAdmin lookup failure must refuse the deprovision, not silently permit it")
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "WithTransaction", mock.Anything, mock.Anything)
	})
}

// TestLocalStorage_UpdateUser_DuplicateEmailWrapsSentinel is the storage-layer half of the
// (#120/#218) regression: UpdateUser must translate a DB-level email-uniqueness violation
// into the clean ErrDuplicateEmail sentinel (mirroring CreateUser), not a raw
// constraint-violation error. See concurrency_scim_update_email_test.go for the full
// concurrent-UpdateSCIMUser race regression.
func TestLocalStorage_UpdateUser_DuplicateEmailWrapsSentinel(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	_ = c
	// Install the same partial unique index production installs get (mirrors
	// factory.go's ensureUserEmailIndex), since newSCIMGuardCore's in-memory AutoMigrate
	// doesn't run the storage-factory migration path that creates it.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive}).Error)

	ls := store.NewLocalStorage(db)
	u2, err := ls.GetUser(ctx, 2)
	require.NoError(t, err)
	u2.Email = "alice@x.io" // collides with user 1
	_, err = ls.UpdateUser(ctx, u2)
	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrDuplicateEmail),
		"a DB-level email collision on UpdateUser must be wrapped in the ErrDuplicateEmail sentinel")
}
