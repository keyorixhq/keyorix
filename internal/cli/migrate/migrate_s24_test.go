// migrate_s24_test.go — additional coverage for runUserToMachine success paths
// and MigrateUserToMachine failure path.
package migrate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// migrateS24DBSeq makes each in-memory DB unique within the process, so that
// repeated invocations of the same test (go test -count=N) don't attach to a
// live leftover DB from a prior iteration.
var migrateS24DBSeq atomic.Int64

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = orig
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// bootstrapFileDBWithProject creates a file-backed SQLite at dbPath, runs
// AutoMigrate, bootstraps the system, creates a project with the given name,
// and closes the connection. Returns the admin email and the project ID.
func bootstrapFileDBWithProject(t *testing.T, dbPath, projectName string) (adminEmail string, projectID uint) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
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
	c.SetBootstrapToken("test-s24-bootstrap-token")
	const email = "admin@s24file.example.com"
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: email,
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-s24-bootstrap-token",
	})
	require.NoError(t, err)

	proj, err := st.CreateProject(context.Background(), &models.Project{Name: projectName})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	return email, proj.ID
}

// bootstrapFileDBWithProjectAndUser is like bootstrapFileDBWithProject but also
// creates a non-admin user with the given username so that MigrateUserToMachine
// has a valid source user to operate on.
func bootstrapFileDBWithProjectAndUser(t *testing.T, dbPath, projectName, username string) string {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
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
	c.SetBootstrapToken("test-s24b-bootstrap-token")
	const email = "admin@s24b.example.com"
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: email,
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-s24b-bootstrap-token",
	})
	require.NoError(t, err)

	_, err = st.CreateProject(context.Background(), &models.Project{Name: projectName})
	require.NoError(t, err)

	// Create the target user that will be migrated.
	_, err = st.CreateUser(context.Background(), &models.User{
		Username: username,
		Email:    fmt.Sprintf("%s@example.com", username),
		IsActive: true,
	})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	return email
}

// ---------------------------------------------------------------------------
// resolveProjectID — project not found after list succeeds (direct call)
// ---------------------------------------------------------------------------

// TestResolveProjectID_NotFoundAfterListSucceeds verifies that resolveProjectID
// returns a "not found" error when ListProjects succeeds but no project matches
// the requested name. This uses an in-memory core with no projects seeded, so
// the list returns an empty slice.
func TestResolveProjectID_NotFoundAfterListSucceeds(t *testing.T) {
	dsn := fmt.Sprintf("file:test_migrate_s24_%s_%d?mode=memory&cache=shared", t.Name(), migrateS24DBSeq.Add(1))
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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
	c.SetBootstrapToken("tok-s24-resolve")
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: "admin@resolve-s24.example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "tok-s24-resolve",
	})
	require.NoError(t, err)

	// Bootstrap seeds no projects, so ListProjects returns an empty slice.
	// Supplying a non-empty flag value bypasses ResolveProject's env/file checks.
	_, err = resolveProjectID(context.Background(), c, "project-that-was-never-created")
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "project"),
		"expected a project-not-found error, got: %v", err)
}

// ---------------------------------------------------------------------------
// requireMigrationAuthority — Authorize returns false for roles.assign
// ---------------------------------------------------------------------------

// TestRequireMigrationAuthority_RolesAssignDenied verifies that an actor who
// has NO permission at all (freshly created, no roles) cannot pass the
// roles.assign check. This is a complementary angle to the authority_test
// coverage using the shared newBootstrappedCore helper.
func TestRequireMigrationAuthority_RolesAssignDenied(t *testing.T) {
	dsn := fmt.Sprintf("file:test_migrate_s24_%s_%d?mode=memory&cache=shared", t.Name(), migrateS24DBSeq.Add(1))
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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
	c.SetBootstrapToken("tok-s24-roles")
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: "admin@roles-s24.example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "tok-s24-roles",
	})
	require.NoError(t, err)

	// Create a bare user with no roles assigned.
	bareUser, err := st.CreateUser(context.Background(), &models.User{
		Username: "bare-user-s24", Email: "bare@roles-s24.example.com", IsActive: true,
	})
	require.NoError(t, err)

	err = requireMigrationAuthority(context.Background(), c, bareUser.ID, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// ---------------------------------------------------------------------------
// requireMigrationAuthority — Authorize returns false for users.write
// ---------------------------------------------------------------------------

// TestRequireMigrationAuthority_UsersWriteDenied verifies that an actor who
// holds roles.assign at the project (via the project_admin role) but lacks
// users.write globally is refused. Uses newBootstrappedCore and seedUserWithRole
// from the sibling authority test file.
func TestRequireMigrationAuthority_UsersWriteDenied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// project_admin grants roles.assign but NOT users.write.
	actor, err := st.CreateUser(ctx, &models.User{
		Username: "s24-proj-admin", Email: "s24-proj-admin@example.com", IsActive: true,
	})
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, actor.ID, role.ID, core.Scope{ProjectID: 1}))

	err = requireMigrationAuthority(ctx, c, actor.ID, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
}

// ---------------------------------------------------------------------------
// runUserToMachine — success with u2mKeepUser=true
// ---------------------------------------------------------------------------

// TestRunUserToMachine_SuccessKeepUser exercises the full happy path of
// runUserToMachine with --keep-user=true. The source user is NOT suspended, so
// the "Source user suspended" message must NOT appear in stdout.
func TestRunUserToMachine_SuccessKeepUser(t *testing.T) {
	resetU2MVars(t)

	dbPath := filepath.Join(t.TempDir(), "s24-keepuser.db")
	adminEmail := bootstrapFileDBWithProjectAndUser(t, dbPath, "s24-proj-keepuser", "svc-account-keep")

	writeConfigYAML(t, "storage:\n  type: local\n  database:\n    path: "+dbPath+"\n")

	u2mBy = adminEmail
	u2mProject = "s24-proj-keepuser"
	u2mKeepUser = true

	var runErr error
	out := captureStdout(t, func() {
		runErr = runUserToMachine(userToMachineCmd, []string{"svc-account-keep"})
	})
	require.NoError(t, runErr)

	// Should report the migration result.
	assert.Contains(t, out, "svc-account-keep")
	// With --keep-user the suspension notice must not appear.
	assert.NotContains(t, out, "suspended")
}

// ---------------------------------------------------------------------------
// runUserToMachine — MigrateUserToMachine fails
// ---------------------------------------------------------------------------

// TestRunUserToMachine_MigrateFails exercises the error path where authority
// checks pass but MigrateUserToMachine fails because the target username does
// not exist in the database.
func TestRunUserToMachine_MigrateFails(t *testing.T) {
	resetU2MVars(t)

	dbPath := filepath.Join(t.TempDir(), "s24-migratefail.db")
	adminEmail, _ := bootstrapFileDBWithProject(t, dbPath, "s24-proj-migratefail")

	writeConfigYAML(t, "storage:\n  type: local\n  database:\n    path: "+dbPath+"\n")

	u2mBy = adminEmail
	u2mProject = "s24-proj-migratefail"
	// "ghost-user" was never inserted into the DB, so MigrateUserToMachine fails.
	err := runUserToMachine(userToMachineCmd, []string{"ghost-user"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "migration failed")
}
