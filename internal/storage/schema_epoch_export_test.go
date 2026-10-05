package storage

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TestInspectMigrationState_FreshDatabase_NoTables covers the "keyorix-server
// admin diagnose" case of a brand-new, never-opened database: no tables at
// all, not even system_metadata.
func TestInspectMigrationState_FreshDatabase_NoTables(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	db, err := gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
	require.NoError(t, err)

	upToDate, detail, err := InspectMigrationState(db)
	require.NoError(t, err)
	require.False(t, upToDate)
	require.Contains(t, detail, "no tables yet")
	require.Contains(t, detail, "admin migrate")
}

// TestInspectMigrationState_FullyMigrated_ReportsUpToDate covers a database
// this binary has already migrated: InspectMigrationState must agree with
// migrateDatabase's own schema-epoch bookkeeping.
func TestInspectMigrationState_FullyMigrated_ReportsUpToDate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "migrated.db")
	db, err := gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	upToDate, detail, err := InspectMigrationState(db)
	require.NoError(t, err)
	require.True(t, upToDate)
	require.Contains(t, detail, "matches this binary")
}

// TestInspectMigrationState_NewerBinaryEpoch_ReportsBehindNotError covers a
// database migrated by an OLDER binary (a lower recorded schema_epoch than
// currentSchemaEpoch): this must be reported as "behind, run admin migrate"
// (upToDate=false), NOT as an error -- it's the routine, expected state of
// an install that hasn't upgraded yet, not a failure of the check itself.
// (checkSchemaEpoch's OWN error path -- the DB newer than this binary -- is
// already covered by the existing TestCheckSchemaEpoch_* tests in this
// package; InspectMigrationState just propagates that same error.)
func TestInspectMigrationState_OlderRecordedEpoch_ReportsBehind(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "stale-epoch.db")
	db, err := gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	// Overwrite the just-recorded (up-to-date) epoch with one behind this
	// binary's, simulating a database an OLDER binary migrated.
	require.NoError(t, db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemMetadata{
		Key:       schemaEpochMetadataKey,
		Value:     strconv.Itoa(currentSchemaEpoch - 1),
		UpdatedAt: time.Now(),
	}).Error)

	upToDate, detail, err := InspectMigrationState(db)
	require.NoError(t, err)
	require.False(t, upToDate)
	require.Contains(t, detail, "behind")
	require.Contains(t, detail, "admin migrate")
}
