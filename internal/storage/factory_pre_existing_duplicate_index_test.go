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

// TestDynamicSecretConfigNameIndex_DedupesPreExistingDuplicates pins #490: the
// #462 fix (ensureDynamicSecretConfigNameIndex) creates a bare
// `CREATE UNIQUE INDEX` on (project_id, environment_id, name) with no
// pre-migration cleanup pass. Any install that already accumulated duplicate
// rows before that index existed — via the very check-then-create race the
// index was meant to close, a bulk import, or a restore — would previously
// hit a hard migration failure on upgrade, blocking the server from starting
// at all. The migration must instead dedupe first (keeping the lowest-id /
// earliest-created row per duplicate group) so the index can always be
// created, and the resulting index must actually reject a fresh duplicate
// insert afterward.
func TestDynamicSecretConfigNameIndex_DedupesPreExistingDuplicates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dynconfig-dedup.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Create the table WITHOUT the unique index — mirrors a pre-#462 database.
	// AutoMigrate never adds the index: the struct intentionally carries no
	// uniqueIndex tag (see DynamicSecretConfig's own doc comment).
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))

	// Seed pre-existing duplicates directly via raw insert, bypassing any
	// app-level uniqueness check entirely — the exact #490 scenario.
	dup1 := &models.DynamicSecretConfig{Name: "pg-app", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}
	require.NoError(t, db.Create(dup1).Error)
	dup2 := &models.DynamicSecretConfig{Name: "pg-app", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}
	require.NoError(t, db.Create(dup2).Error)
	dup3 := &models.DynamicSecretConfig{Name: "pg-app", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}
	require.NoError(t, db.Create(dup3).Error)
	// A row under a different key must be left untouched.
	other := &models.DynamicSecretConfig{Name: "pg-other", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}
	require.NoError(t, db.Create(other).Error)

	var countBefore int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&countBefore).Error)
	require.Equal(t, int64(4), countBefore)

	// (a) The migration step must NOT error on the pre-existing duplicates.
	require.NoError(t, ensureDynamicSecretConfigNameIndex(db))

	// (b) Exactly one survivor per duplicate group — the lowest-id (earliest
	// created) row.
	var survivors []models.DynamicSecretConfig
	require.NoError(t, db.Where("project_id = ? AND environment_id = ? AND name = ?", 1, 1, "pg-app").Find(&survivors).Error)
	require.Len(t, survivors, 1, "only one row per duplicate group must survive")
	assert.Equal(t, dup1.ID, survivors[0].ID, "the lowest-id (earliest-created) row must be the survivor")

	var otherCount int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Where("id = ?", other.ID).Count(&otherCount).Error)
	assert.Equal(t, int64(1), otherCount, "a row under a different key must be untouched")

	// (c) The index now exists and rejects a fresh duplicate insert.
	err = db.Create(&models.DynamicSecretConfig{Name: "pg-app", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}).Error
	require.Error(t, err, "the unique index must now reject a duplicate (project, env, name) insert")

	// Re-running the migration step (simulating a later boot, once the index
	// already exists) must be a pure no-op: no error, no further row loss, and
	// no re-scan for duplicates (guarded by indexExists).
	require.NoError(t, ensureDynamicSecretConfigNameIndex(db))
	var countAfter int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&countAfter).Error)
	assert.Equal(t, int64(2), countAfter, "survivor + untouched row only")
}

// TestDynamicSecretConfigNameIndex_FullBootDoesNotHardFail exercises the real
// production entry point end to end: CreateStorage -> migrateDatabase against
// a database file that already has duplicate dynamic_secret_configs rows
// before the process ever calls it (simulating an upgrade of a pre-#462
// install). Boot must succeed, not error out.
func TestDynamicSecretConfigNameIndex_FullBootDoesNotHardFail(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "dynconfig-boot-dedup.db")

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
	require.NoError(t, err, "boot must not hard-fail on pre-existing dynamic_secret_configs duplicates (#490)")
}

// TestProjectMembershipIndex_DedupesPreExistingDuplicates sanity-checks the
// shared dedupeBeforeUniqueIndex helper against a *partial* index (scoped by a
// WHERE predicate), not just the plain index the primary #462/#490 case above
// covers — proving the fix generalizes to the sibling ensure*Index helpers.
func TestProjectMembershipIndex_DedupesPreExistingDuplicates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "membership-dedup.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}))

	live1 := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active"}
	require.NoError(t, db.Create(live1).Error)
	live2 := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active"}
	require.NoError(t, db.Create(live2).Error)
	// A revoked row for the same (project, user) must be left alone — it falls
	// outside the partial index's WHERE state <> 'revoked' predicate.
	revoked := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "revoked"}
	require.NoError(t, db.Create(revoked).Error)

	require.NoError(t, ensureProjectMembershipIndex(db))

	var liveRows []models.ProjectMembership
	require.NoError(t, db.Where("project_id = ? AND user_id = ? AND state <> 'revoked'", 1, 1).Find(&liveRows).Error)
	require.Len(t, liveRows, 1, "only one non-revoked row per (project, user) must survive")
	assert.Equal(t, live1.ID, liveRows[0].ID)

	var revokedCount int64
	require.NoError(t, db.Model(&models.ProjectMembership{}).Where("id = ?", revoked.ID).Count(&revokedCount).Error)
	assert.Equal(t, int64(1), revokedCount, "the revoked row (outside the partial predicate) must be untouched")

	err = db.Create(&models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active"}).Error
	require.Error(t, err, "the partial unique index must reject a second non-revoked row for the same (project, user)")
}

// gormOpenForTest opens a fresh SQLite connection at dbPath using the same
// DSN/config the production factory uses, for tests that need to drive the
// migration helpers directly against a hand-seeded database.
func gormOpenForTest(t *testing.T, dbPath string) (*gorm.DB, error) {
	t.Helper()
	return gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
}
