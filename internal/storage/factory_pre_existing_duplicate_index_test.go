package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestDynamicSecretConfigNameIndex_FailsLoudOnPreExistingDuplicates pins #490:
// the #462 fix (ensureDynamicSecretConfigNameIndex) creates a bare
// `CREATE UNIQUE INDEX` on (project_id, environment_id, name) with no
// pre-migration check. Any install that already accumulated duplicate rows
// before that index existed — via the very check-then-create race the index
// was meant to close, a bulk import, or a restore — would otherwise hit an
// opaque driver-level constraint-violation error deep inside migrateDatabase.
//
// Two rows colliding on (project, env, name) can carry different AdminDSNEnc/
// CreationTemplate/BackendType values (they are not guaranteed to be
// redundant repeats of the same event), so the migration must NOT silently
// delete either one — it must fail with a clear, actionable error naming the
// conflicting table and pointing the operator at a real remediation path,
// leaving both rows untouched.
func TestDynamicSecretConfigNameIndex_FailsLoudOnPreExistingDuplicates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dynconfig-dup.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Create the table WITHOUT the unique index — mirrors a pre-#462 database.
	// AutoMigrate never adds the index: the struct intentionally carries no
	// uniqueIndex tag (see DynamicSecretConfig's own doc comment).
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))

	// Seed pre-existing duplicates directly via raw insert, bypassing any
	// app-level uniqueness check entirely — the exact #490 scenario. The two
	// rows deliberately carry different BackendType/CreationTemplate values to
	// demonstrate they are not necessarily redundant.
	dup1 := &models.DynamicSecretConfig{Name: "pg-app", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres", CreationTemplate: "GRANT SELECT ...;"}
	require.NoError(t, db.Create(dup1).Error)
	dup2 := &models.DynamicSecretConfig{Name: "pg-app", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres", CreationTemplate: "GRANT ALL ...;"}
	require.NoError(t, db.Create(dup2).Error)
	// A row under a different key must be left untouched.
	other := &models.DynamicSecretConfig{Name: "pg-other", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}
	require.NoError(t, db.Create(other).Error)

	var countBefore int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&countBefore).Error)
	require.Equal(t, int64(3), countBefore)

	// The migration step must fail loud instead of silently deleting a row.
	err = ensureDynamicSecretConfigNameIndex(db)
	require.Error(t, err, "pre-existing duplicates must block the migration with an actionable error, not be silently deleted")
	assert.Contains(t, err.Error(), "dynamic_secret_configs")
	assert.Contains(t, err.Error(), "dynamic-secret-config API")

	// No row was touched: both duplicates and the unrelated row still exist.
	var countAfter int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&countAfter).Error)
	assert.Equal(t, int64(3), countAfter, "no row may be deleted by a failed migration check")

	var survivingDup2 models.DynamicSecretConfig
	require.NoError(t, db.First(&survivingDup2, dup2.ID).Error, "dup2 must not have been deleted")
}

// TestDynamicSecretConfigNameIndex_FullBootHardFailsOnPreExistingDuplicates
// exercises the real production entry point end to end: CreateStorage ->
// migrateDatabase against a database file that already has duplicate
// dynamic_secret_configs rows before the process ever calls it (simulating an
// upgrade of a pre-#462 install). Boot must fail with the actionable
// warnIfDuplicatesExist error rather than an opaque driver-level constraint
// violation — and, per #490, must not have deleted either conflicting row.
func TestDynamicSecretConfigNameIndex_FullBootHardFailsOnPreExistingDuplicates(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "dynconfig-boot-dup.db")

	// Simulate a pre-#462 database: create only the dynamic_secret_configs
	// table (no unique index) and seed duplicates directly, then close this
	// connection before the real boot path opens its own.
	seedDB, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	require.NoError(t, seedDB.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, seedDB.Create(&models.DynamicSecretConfig{Name: "shared", ProjectID: 5, EnvironmentID: 1, BackendType: "postgres"}).Error)
	require.NoError(t, seedDB.Create(&models.DynamicSecretConfig{Name: "shared", ProjectID: 5, EnvironmentID: 1, BackendType: "postgres"}).Error)
	sqlDB, err := seedDB.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath

	_, err = NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err, "boot must fail loud (not silently delete a row) on pre-existing dynamic_secret_configs duplicates (#490)")
	assert.Contains(t, err.Error(), "dynamic_secret_configs")

	// Re-open directly and confirm both conflicting rows are still present.
	verifyDB, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	var count int64
	require.NoError(t, verifyDB.Model(&models.DynamicSecretConfig{}).Where("project_id = ? AND environment_id = ? AND name = ?", 5, 1, "shared").Count(&count).Error)
	assert.Equal(t, int64(2), count, "a failed migration check must not delete either conflicting row")
}

// TestProjectMembershipIndex_FailsLoudOnPreExistingDuplicates sanity-checks
// warnIfDuplicatesExist against a *partial* index (scoped by a WHERE
// predicate), not just the plain index the dynamic_secret_configs case above
// covers — proving the fail-loud behavior generalizes to the sibling
// ensure*Index helpers. Two non-revoked memberships for the same (project,
// user) can carry different Role values (the #309 fix comment explicitly
// calls this out), so the migration must not guess which one is correct by
// deleting the other.
func TestProjectMembershipIndex_FailsLoudOnPreExistingDuplicates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "membership-dup.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}))

	live1 := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active", Role: "viewer"}
	require.NoError(t, db.Create(live1).Error)
	live2 := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active", Role: "admin"}
	require.NoError(t, db.Create(live2).Error)
	// A revoked row for the same (project, user) must be left alone — it falls
	// outside the partial index's WHERE state <> 'revoked' predicate.
	revoked := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "revoked"}
	require.NoError(t, db.Create(revoked).Error)

	err = ensureProjectMembershipIndex(db)
	require.Error(t, err, "pre-existing non-revoked duplicates must block the migration with an actionable error, not be silently deleted")
	assert.Contains(t, err.Error(), "project_memberships")
	assert.Contains(t, err.Error(), "membership-revoke API")

	// Neither conflicting row was touched.
	var liveRows []models.ProjectMembership
	require.NoError(t, db.Where("project_id = ? AND user_id = ? AND state <> 'revoked'", 1, 1).Find(&liveRows).Error)
	require.Len(t, liveRows, 2, "a failed migration check must not delete either conflicting non-revoked row")

	var revokedCount int64
	require.NoError(t, db.Model(&models.ProjectMembership{}).Where("id = ?", revoked.ID).Count(&revokedCount).Error)
	assert.Equal(t, int64(1), revokedCount, "the revoked row (outside the partial predicate) must be untouched")
}

// gormOpenForTest opens a fresh SQLite connection at dbPath using the same
// DSN/config the production factory uses, for tests that need to drive the
// migration helpers directly against a hand-seeded database.
func gormOpenForTest(t *testing.T, dbPath string) (*gorm.DB, error) {
	t.Helper()
	return gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
}
