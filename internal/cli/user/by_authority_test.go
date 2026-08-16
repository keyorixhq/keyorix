// by_authority_test.go — regression coverage for the impersonation-ceiling
// finding (adversarial-review findings-unreviewed/internal-cli.json#4,
// tracked as fix-wave5-g05): resolveAdminID resolved --by to a user ID with
// ZERO authority check, so any local operator could attribute a destructive
// account-lifecycle action (suspend/delete/etc.) to an arbitrary admin's
// identity purely by naming their email on --by, poisoning the audit trail.
//
// Sibling of internal/cli/invite/send_authority_test.go and
// internal/cli/request/review_authority_test.go (#264/#491): the fix adds
// requireUserAuthority, verified here both directly and through the
// user-facing commands that call it (suspend/delete), confirming an
// unprivileged --by actor is now refused rather than silently credited.
package user

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newByAuthorityTestCore spins up an in-memory store, runs the production
// BootstrapSystem (seeding the real RBAC role/permission catalog), and returns
// the core + storage for authority assertions — mirrors
// invite.newTestInviteCore / request's equivalent helper.
func newByAuthorityTestCore(t *testing.T) (*core.KeyorixCore, *store.LocalStorage) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.PersonalAccessToken{}, &models.Session{}, &models.AuditEvent{},
		&models.PasswordHistory{},
	))
	st := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(st)
	c.SetBootstrapToken("by-authority-test-token")
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "S3cur3!P@ssw0rd#2026",
		DisplayName: "Admin", Token: "by-authority-test-token",
	})
	require.NoError(t, err)
	return c, st
}

// seedByAuthorityUserWithRole creates a user and assigns roleName at scope,
// returning the new user's ID.
func seedByAuthorityUserWithRole(t *testing.T, st *store.LocalStorage, username, roleName string, scope core.Scope) uint {
	t.Helper()
	ctx := context.Background()
	u, err := st.CreateUser(ctx, &models.User{Username: username, Email: username + "@example.com", IsActive: true})
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoErrorf(t, err, "role %s must be seeded", roleName)
	require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, scope))
	return u.ID
}

// ──────────────────────── requireUserAuthority: direct unit coverage ────────

// An actor holding only "viewer" (users.read, not users.write/users.delete)
// must be refused for both permissions the account-lifecycle commands need —
// the CLI must not let --by attribute the action to an unprivileged account.
func TestRequireUserAuthority_UnprivilegedActorRejected(t *testing.T) {
	c, st := newByAuthorityTestCore(t)
	ctx := context.Background()
	actor := seedByAuthorityUserWithRole(t, st, "user-viewer", "viewer", core.Scope{})

	err := requireUserAuthority(ctx, c, actor, permUsersWrite)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
	assert.Contains(t, err.Error(), "refusing to attribute")

	err = requireUserAuthority(ctx, c, actor, permUsersDelete)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.delete")
}

// An actor with NO role at all (zero role IDs resolved) must also be
// refused, not silently treated as authorized.
func TestRequireUserAuthority_NoRoleActorRejected(t *testing.T) {
	c, st := newByAuthorityTestCore(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, &models.User{Username: "roleless", Email: "roleless@example.com", IsActive: true})
	require.NoError(t, err)

	err = requireUserAuthority(ctx, c, u.ID, permUsersWrite)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not hold users.write")
}

// The bootstrap admin (the realistic legitimate --by actor for these
// commands) must be allowed through for both permissions.
func TestRequireUserAuthority_BootstrapAdminAllowed(t *testing.T) {
	c, st := newByAuthorityTestCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	require.NoError(t, requireUserAuthority(ctx, c, admin.ID, permUsersWrite))
	require.NoError(t, requireUserAuthority(ctx, c, admin.ID, permUsersDelete))
}

// ──────────── end-to-end: the exploit scenario is now refused ──────────────

// TestRunLifecycle_UnprivilegedByRejected reproduces the exact exploit: a
// local operator invokes `keyorix user suspend --by <victim-admin-email>`
// where victim-admin holds no users.write permission. Pre-fix, resolveAdminID
// would happily resolve the email and SuspendUser would be credited to them
// with zero verification. Post-fix, the operation must be refused before
// SuspendUser is ever called.
func TestRunLifecycle_UnprivilegedByRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	// Seed a second, unprivileged user directly against the same file-backed
	// DB that seedUserDB/InitializeCoreService just created, so --by resolves
	// to a REAL user record that simply lacks users.write.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()
	victim, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: "victim-admin", Email: "victim-admin@example.com",
		DisplayName: "Victim Admin", Password: "V1ct1m!P@ssw0rd#2026",
	})
	require.NoError(t, err)

	err = runLifecycle(targetID, "victim-admin@example.com", "suspended",
		func(s *core.KeyorixCore, c context.Context, adminID, userID uint) error {
			return s.SuspendUser(c, adminID, userID)
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
	assert.Contains(t, err.Error(), "refusing to attribute")

	// Confirm the target user was NOT actually suspended — the rejection
	// happened before SuspendUser was reached.
	u, err := svc.GetUser(ctx, targetID)
	require.NoError(t, err)
	assert.True(t, u.IsActive, "target must remain active: the unauthorized --by suspend must not have applied")
	_ = victim.ID
}

// TestRunDelete_UnprivilegedByRejected is the delete-path sibling: --by
// naming an unprivileged user must be refused (users.delete), not silently
// credited as the deleting actor.
func TestRunDelete_UnprivilegedByRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, targetID := seedUserDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()
	_, err = svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: "victim-admin2", Email: "victim-admin2@example.com",
		DisplayName: "Victim Admin 2", Password: "V1ct1m!P@ssw0rd#2026",
	})
	require.NoError(t, err)

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID = targetID
	deleteBy = "victim-admin2@example.com"
	deleteForce = true

	err = runDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.delete")
	assert.Contains(t, err.Error(), "refusing to attribute")

	// Confirm the target user was NOT actually deleted.
	u, err := svc.GetUser(ctx, targetID)
	require.NoError(t, err)
	require.NotNil(t, u)
}
