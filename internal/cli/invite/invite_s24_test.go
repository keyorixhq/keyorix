// invite_s24_test.go — coverage sprint 24 for internal/cli/invite.
// Targets:
//   - runSend: inv != nil, err != nil (partial-success / link-delivery-failed) branch
//   - requireInviteAuthority: Authorize storage error → "failed to verify --by authority"
//   - resendCmd.RunE: resendID == 0, resendBy == "" guard branches
//   - resendCmd.RunE: invitation not found path (valid user, non-existent invitation)
//   - runRevoke: user not found path (seeded DB, unknown revokeBy)
//   - runRevoke: invitation not found path (valid user, non-existent invitation ID)
package invite

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newTestInviteCoreWithDB is like newTestInviteCore but also returns the
// underlying *gorm.DB so callers can close the connection pool to force
// storage errors in subsequent operations.
func newTestInviteCoreWithDB(t *testing.T) (*core.KeyorixCore, *store.LocalStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.PersonalAccessToken{}, &models.Session{}, &models.AuditEvent{},
	))

	st := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token-s24")
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token-s24",
	})
	require.NoError(t, err)
	return c, st, db
}

// ──────────────────────────── runSend ────────────────────────────────────────

// TestRunSend_PartialSuccess_LinkDeliveryFailed verifies the branch in runSend
// where InviteToProjectWithLink returns a non-nil invitation together with a
// non-nil error (the invitation was persisted but the setup link could not be
// delivered because base_url is unset).  The function must return an error
// whose message contains "setup link could not be delivered".
func TestRunSend_PartialSuccess_LinkDeliveryFailed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	_, _ = seedInviteDB(t)

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "partial@example.com"
	sendRole = "project_viewer"
	sendBy = "admin@example.com"
	sendProject = "default"

	// InitializeCoreService reads the seeded file DB; since SetCredentialDelivery
	// is never called (no base_url in config), provisionSetupLinkThrottled returns
	// ErrSetupBaseURLRequired.  InviteToProjectWithLink returns (inv, nil, err)
	// with inv != nil — the partial-success branch in runSend.
	err := runSend(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup link could not be delivered")
}

// ──────────────────────────── requireInviteAuthority ─────────────────────────

// TestRequireInviteAuthority_AuthorizeError verifies that when the storage
// layer fails (simulated by closing the DB connection after bootstrapping),
// requireInviteAuthority wraps the error with "failed to verify --by authority".
func TestRequireInviteAuthority_AuthorizeError(t *testing.T) {
	c, _, db := newTestInviteCoreWithDB(t)
	ctx := context.Background()

	// Retrieve the admin user ID before closing the connection.
	adminUser, err := c.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	// Close the underlying connection pool so every subsequent DB call fails.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	authErr := requireInviteAuthority(ctx, c, adminUser.ID, 1)
	require.Error(t, authErr)
	assert.Contains(t, authErr.Error(), "failed to verify --by authority")
}

// ──────────────────────────── resendCmd.RunE guard branches ──────────────────

// TestResendCmd_IDZeroGuard verifies that resendCmd.RunE returns
// "invitation id is required" when resendID is 0.
func TestResendCmd_IDZeroGuard(t *testing.T) {
	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = 0
	resendBy = "admin@example.com"

	err := resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invitation id is required")
}

// TestResendCmd_ByEmptyGuard verifies that resendCmd.RunE returns
// "acting admin email is required" when resendBy is empty.
func TestResendCmd_ByEmptyGuard(t *testing.T) {
	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = 1
	resendBy = ""

	err := resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acting admin email is required")
}

// ──────────────────────────── resendCmd — invitation not found ────────────────

// TestResendCmd_InvitationNotFound exercises the GetProjectInvitation error
// branch: the actor (admin@example.com) resolves successfully, but invitation
// ID 999999 does not exist, so the command returns "not found".
func TestResendCmd_InvitationNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedInviteDB(t)

	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = 999999
	resendBy = "admin@example.com"

	err := resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ──────────────────────────── runRevoke — error paths ────────────────────────

// TestRunRevoke_UserNotFound verifies that runRevoke returns a user-resolution
// error when revokeBy resolves to no user in the seeded DB.
func TestRunRevoke_UserNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedInviteDB(t)

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	revokeID = 1
	revokeBy = "nobody@example.com"

	err := runRevoke(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nobody@example.com")
}

// TestRunRevoke_InvitationNotFound verifies that runRevoke returns
// "invitation N not found" when revokeID refers to a non-existent invitation
// but the actor resolves correctly.
func TestRunRevoke_InvitationNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _ = seedInviteDB(t)

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	revokeID = 999999
	revokeBy = "admin@example.com"

	err := runRevoke(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
