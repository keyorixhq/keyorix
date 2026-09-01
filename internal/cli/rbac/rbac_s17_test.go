// rbac_s17_test.go — coverage sprint 17 for internal/cli/rbac.
// Targets the "has data" branches in the embedded-mode run functions:
//   - runListRoles: the "has roles" branch (len(roles) > 0)
//   - runListUserRoles: the "has roles" branch (len(roles) > 0)
//   - runListPermissions: the "has permissions" branch (len(permissions) > 0)
//   - runAuditLogsEmbedded: the "has entries" branch (len(entries) > 0)
//
// Strategy: use t.Chdir(dir) + write keyorix.yaml so InitializeStorage() and
// InitializeCoreService() both point at the same ./secrets.db in the temp dir.
// Call common.InitializeCoreService() first (which initializes i18n via sync.Once
// so GetUserByEmail's i18n.T() call doesn't panic), then seed the DB directly via
// the storage factory before invoking the run functions.
package rbac

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// initEmbeddedDB sets up a temp dir with keyorix.yaml, initializes i18n and the
// schema via InitializeCoreService, and returns the DB path so callers can open a
// second storage instance for seeding. t.Cleanup handles the temp dir.
func initEmbeddedDB(t *testing.T) (dbPath string, seedSt corestorage.Storage) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	dbPath = filepath.Join(dir, "secrets.db")
	yaml := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	// InitializeCoreService initialises i18n (sync.Once) and runs AutoMigrate,
	// creating all tables in the SQLite file.
	_, err := common.InitializeCoreService()
	require.NoError(t, err)

	// Open a second handle on the same DB for seeding test data.
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: dbPath},
		},
	}
	// i18n is already initialised; this is a no-op but harmless.
	_ = i18n.Initialize(cfg)

	factory := storage.NewStorageFactory()
	seedSt, err = factory.CreateStorage(cfg)
	require.NoError(t, err)

	return dbPath, seedSt
}

// ── runListRoles — "has roles" branch ────────────────────────────────────────

// TestListRoles_EmbeddedMode_WithRoles exercises the "Available roles:" branch
// (len(roles) > 0) in runListRoles. Seeds two roles directly into the DB, then
// calls runListRoles and verifies no error.
func TestListRoles_EmbeddedMode_WithRoles(t *testing.T) {
	_, st := initEmbeddedDB(t)

	ctx := context.Background()
	s17AdminName, err := identity.NewFoldedName("s17_admin")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, s17AdminName, "S17 Admin")
	require.NoError(t, err)
	s17ViewerName, err := identity.NewFoldedName("s17_viewer")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, s17ViewerName, "S17 Viewer")
	require.NoError(t, err)

	errRun := runListRoles(nil, nil)
	require.NoError(t, errRun, "runListRoles should succeed when roles exist")
}

// ── runListUserRoles — "has roles" / "empty roles" branches ──────────────────

// TestListUserRoles_EmbeddedMode_UserWithRoles exercises the "has roles" branch
// in runListUserRoles. Seeds a user and assigns a role to them.
func TestListUserRoles_EmbeddedMode_UserWithRoles(t *testing.T) {
	_, st := initEmbeddedDB(t)

	ctx := context.Background()
	const testEmail = "haseroles_s17@example.com"

	user, err := st.CreateUser(ctx, &models.User{
		Username: "haseroles_s17",
		Email:    testEmail,
	})
	require.NoError(t, err)

	s17EditorName, err := identity.NewFoldedName("s17_editor")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, s17EditorName, "S17 Editor")
	require.NoError(t, err)

	require.NoError(t, st.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{}))

	orig := listUserEmail
	defer func() { listUserEmail = orig }()
	listUserEmail = testEmail

	errRun := runListUserRoles(nil, nil)
	require.NoError(t, errRun, "runListUserRoles should succeed when user has roles")
}

// TestListUserRoles_EmbeddedMode_EmptyRoles exercises the "No roles assigned" branch:
// user exists but has no roles.
func TestListUserRoles_EmbeddedMode_EmptyRoles(t *testing.T) {
	_, st := initEmbeddedDB(t)

	ctx := context.Background()
	const testEmail = "noroles_s17@example.com"

	_, err := st.CreateUser(ctx, &models.User{
		Username: "noroles_s17",
		Email:    testEmail,
	})
	require.NoError(t, err)

	orig := listUserEmail
	defer func() { listUserEmail = orig }()
	listUserEmail = testEmail

	errRun := runListUserRoles(nil, nil)
	require.NoError(t, errRun, "No roles assigned branch should not error")
}

// ── runListPermissions — "has permissions" / "no permissions" branches ────────

// TestListPermissions_EmbeddedMode_UserWithPermissions exercises the
// "Permissions for user" branch in runListPermissions.
func TestListPermissions_EmbeddedMode_UserWithPermissions(t *testing.T) {
	_, st := initEmbeddedDB(t)

	ctx := context.Background()
	const testEmail = "hasperm_s17@example.com"

	user, err := st.CreateUser(ctx, &models.User{
		Username: "hasperm_s17",
		Email:    testEmail,
	})
	require.NoError(t, err)

	s17PermRoleName, err := identity.NewFoldedName("s17_permrole")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, s17PermRoleName, "S17 perm role")
	require.NoError(t, err)

	perm, err := st.CreatePermission(ctx, &models.Permission{
		Name:        "secrets.s17test",
		Description: "S17 test perm",
		Resource:    "secrets",
		Action:      "s17test",
	})
	require.NoError(t, err)

	require.NoError(t, st.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{}))
	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, perm.ID))

	orig := listPermissionsUserEmail
	defer func() { listPermissionsUserEmail = orig }()
	listPermissionsUserEmail = testEmail

	errRun := runListPermissions(nil, nil)
	require.NoError(t, errRun, "runListPermissions should succeed when user has permissions")
}

// TestListPermissions_EmbeddedMode_NoPermissions exercises the "No permissions found"
// branch — user exists but has no roles or permissions.
func TestListPermissions_EmbeddedMode_NoPermissions(t *testing.T) {
	_, st := initEmbeddedDB(t)

	ctx := context.Background()
	const testEmail = "noperms_s17@example.com"

	_, err := st.CreateUser(ctx, &models.User{
		Username: "noperms_s17",
		Email:    testEmail,
	})
	require.NoError(t, err)

	orig := listPermissionsUserEmail
	defer func() { listPermissionsUserEmail = orig }()
	listPermissionsUserEmail = testEmail

	errRun := runListPermissions(nil, nil)
	require.NoError(t, errRun, "No permissions branch should not error")
}

// ── runAuditLogsEmbedded — "has entries" branch ───────────────────────────────

// TestAuditLogsEmbedded_WithEntries exercises the "RBAC audit logs (showing ...)"
// branch in runAuditLogsEmbedded by inserting an RBAC audit event directly into
// the audit_events table, then calling runAuditLogs.
func TestAuditLogsEmbedded_WithEntries(t *testing.T) {
	_, st := initEmbeddedDB(t)

	ctx := context.Background()

	// Insert a role.assigned event using LogAuditEvent — this is the same type
	// that ListRBACAuditLogs filters for.
	now := time.Now().UTC()
	require.NoError(t, st.LogAuditEvent(ctx, &models.AuditEvent{
		EventType:   "role.assigned",
		Description: "s17 test role assignment",
		EventTime:   now,
		Diff:        `{"role_id":1,"target_user_id":2}`,
	}))

	origL, origO := auditLimit, auditOffset
	defer func() { auditLimit = origL; auditOffset = origO }()
	auditLimit = 50
	auditOffset = 0

	errRun := runAuditLogs(nil, nil)
	assert.NoError(t, errRun, "runAuditLogs should succeed when audit entries exist")
}
