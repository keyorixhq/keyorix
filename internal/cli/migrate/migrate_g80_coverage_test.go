// migrate_g80_coverage_test.go — closes the remaining reasonably-reachable gaps
// left after the s3/s24 waves: the runUserToMachine branch that PROPAGATES a
// requireMigrationAuthority failure through the full command (rather than
// calling requireMigrationAuthority directly), and the default (--keep-user
// unset) success path that prints the "Source user suspended" notice.
package migrate

import (
	"context"
	"fmt"
	"path/filepath"
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

// bootstrapFileDBWithProjectAndUnprivilegedActor is like
// bootstrapFileDBWithProjectAndUser (migrate_s24_test.go) but the extra user it
// creates holds no roles at all, so it is unfit to be credited as the acting
// admin for a migration. Returns that user's email for use as --by.
func bootstrapFileDBWithProjectAndUnprivilegedActor(t *testing.T, dbPath, projectName, actorUsername string) (actorEmail string) {
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
	c.SetBootstrapToken("test-g80-bootstrap-token")
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: "admin@g80.example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-g80-bootstrap-token",
	})
	require.NoError(t, err)

	_, err = st.CreateProject(context.Background(), &models.Project{Name: projectName})
	require.NoError(t, err)

	// The actor has an active account but zero role assignments, so it holds
	// neither roles.assign nor users.write.
	actorEmail = fmt.Sprintf("%s@example.com", actorUsername)
	_, err = st.CreateUser(context.Background(), &models.User{
		Username: actorUsername,
		Email:    actorEmail,
		IsActive: true,
	})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	return actorEmail
}

// TestRunUserToMachine_AuthorityCheckFails_FullPipeline exercises the
// requireMigrationAuthority failure branch AS REACHED THROUGH runUserToMachine
// (user_to_machine.go:70-72), rather than by calling requireMigrationAuthority
// directly. --by resolves to a real, active user who nonetheless holds no
// roles at all, so the authority check fails and runUserToMachine must
// propagate that error verbatim without ever calling MigrateUserToMachine.
func TestRunUserToMachine_AuthorityCheckFails_FullPipeline(t *testing.T) {
	resetU2MVars(t)

	dbPath := filepath.Join(t.TempDir(), "g80-authfail.db")
	actorEmail := bootstrapFileDBWithProjectAndUnprivilegedActor(t, dbPath, "g80-proj-authfail", "g80-unpriv-actor")

	writeConfigYAML(t, "storage:\n  type: local\n  database:\n    path: "+dbPath+"\n")

	u2mBy = actorEmail
	u2mProject = "g80-proj-authfail"

	err := runUserToMachine(userToMachineCmd, []string{"some-target-user"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
	// The error must be the authority error, not a wrapped "migration failed"
	// error — proving requireMigrationAuthority's failure short-circuits before
	// MigrateUserToMachine is ever invoked (the target user was never created).
	assert.NotContains(t, err.Error(), "migration failed")
}

// TestRunUserToMachine_SuccessDefaultSuspendsUser exercises the full happy path
// of runUserToMachine with the default --keep-user=false, hitting the
// "Source user suspended" notice branch (user_to_machine.go:81-83) that the
// existing --keep-user=true success test (migrate_s24_test.go) deliberately
// does NOT reach.
func TestRunUserToMachine_SuccessDefaultSuspendsUser(t *testing.T) {
	resetU2MVars(t)

	dbPath := filepath.Join(t.TempDir(), "g80-suspend.db")
	adminEmail := bootstrapFileDBWithProjectAndUser(t, dbPath, "g80-proj-suspend", "svc-account-suspend")

	writeConfigYAML(t, "storage:\n  type: local\n  database:\n    path: "+dbPath+"\n")

	u2mBy = adminEmail
	u2mProject = "g80-proj-suspend"
	u2mKeepUser = false

	var runErr error
	out := captureStdout(t, func() {
		runErr = runUserToMachine(userToMachineCmd, []string{"svc-account-suspend"})
	})
	require.NoError(t, runErr)

	assert.Contains(t, out, "svc-account-suspend")
	assert.Contains(t, out, "Source user suspended (login blocked). Use `keyorix user reactivate` to restore.")
}
