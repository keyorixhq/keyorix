package storage

// factory_schema_epoch_pre3258_refusal_test.go -- UPGRADE-CORRECT-1 items 2 and 3
// (#3359, #3362).
//
// Every released binary predates the v2 audit retention anchor (#3258) and
// secret_nodes.suspend_clear_synced_copies (#3215): no release tag up to v0.96.3
// contains either. Such a binary must not start on a database this binary has
// migrated. Otherwise its retention purge rewrites the anchor as v1 and drops the
// cumulative purged count (#3359), or its resume leaves the clear-copies marker set
// (#3362). On PostgreSQL the triggers still cover a replica that was already running
// when the migration happened (factory_rolling_upgrade_triggers_postgres_test.go).
//
// The start gates below are copies of the released decision logic, not calls into
// this binary's checkSchemaEpochFor. A change here (a lower floor, a floor no longer
// raised on an upgraded database) therefore shows up as an old binary that starts:
//   - v0.93.0 to v0.95.3 (currentSchemaEpoch 1): ADR-097 only. Refuse when the
//     recorded schema_epoch is above 1; no floor support.
//   - v0.96.0 to v0.96.3 (currentSchemaEpoch 2): ADR-101. Refuse when the
//     recorded floor is above 2. If a floor is recorded and is at most 2, START,
//     whatever schema_epoch says. That is why the floor must be raised on an
//     upgraded v0.96 database, not only written on a fresh one.

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func releasedMetadata(t *testing.T, db *gorm.DB, key string) (string, bool) {
	t.Helper()
	var m models.SystemMetadata
	err := db.Where("key = ?", key).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false
	}
	require.NoError(t, err)
	return m.Value, true
}

// releasedADR097Starts is the start decision of v0.93.0 to v0.95.3
// (checkSchemaEpoch with currentSchemaEpoch = 1).
func releasedADR097Starts(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	v, ok := releasedMetadata(t, db, "schema_epoch")
	if !ok {
		return true
	}
	dbEpoch, err := strconv.Atoi(v)
	if err != nil {
		return false
	}
	return dbEpoch <= 1
}

// releasedADR101Starts is the start decision of v0.96.0 to v0.96.3
// (checkSchemaEpochFor(db, 2)).
func releasedADR101Starts(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	const binaryEpoch = 2
	floorV, floorFound := releasedMetadata(t, db, "schema_min_compatible_epoch")
	if floorFound {
		floor, err := strconv.Atoi(floorV)
		if err != nil || floor < 1 || floor > binaryEpoch {
			return false
		}
	}
	v, ok := releasedMetadata(t, db, "schema_epoch")
	if !ok {
		return true
	}
	dbEpoch, err := strconv.Atoi(v)
	if err != nil {
		return false
	}
	if floorFound {
		return true
	}
	return dbEpoch <= binaryEpoch
}

func TestReleasedPreAnchorV2Binaries_RefuseOnMigratedDatabase(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	f := &DefaultStorageFactory{}

	// stamp overwrites the epoch rows as an older release left them.
	stamp := func(t *testing.T, db *gorm.DB, epoch, floor string) {
		t.Helper()
		require.NoError(t, db.Where("key IN ?", []string{schemaEpochMetadataKey, schemaMinCompatibleEpochMetadataKey}).
			Delete(&models.SystemMetadata{}).Error)
		require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: epoch}).Error)
		if floor != "" {
			require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaMinCompatibleEpochMetadataKey, Value: floor}).Error)
		}
	}

	cases := []struct {
		name  string
		setup func(t *testing.T) *gorm.DB
	}{
		{"fresh install", func(t *testing.T) *gorm.DB {
			db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "fresh.db"))
			require.NoError(t, err)
			require.NoError(t, f.migrateDatabase(db))
			return db
		}},
		{"upgraded from the real v0.95.0 fixture", func(t *testing.T) *gorm.DB {
			dbPath := filepath.Join(t.TempDir(), "v095.db")
			copyFileU1(t, filepath.Join(repoRootU1(), "internal", "core", "testdata", "upgrade-fixtures", "v095", "fixture.db"), dbPath)
			db, err := gormOpenForTest(t, dbPath)
			require.NoError(t, err)
			require.True(t, releasedADR097Starts(t, db), "the v0.95.0 fixture must start its own release before the upgrade")
			require.NoError(t, f.migrateDatabase(db))
			return db
		}},
		{"upgraded from a database v0.96.x left (epoch 2, floor 2)", func(t *testing.T) *gorm.DB {
			db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "v096.db"))
			require.NoError(t, err)
			require.NoError(t, f.migrateDatabase(db))
			stamp(t, db, "2", "2")
			require.True(t, releasedADR101Starts(t, db), "v0.96.x must start on the database it left")
			require.NoError(t, f.migrateDatabase(db))
			return db
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := c.setup(t)
			require.False(t, releasedADR097Starts(t, db),
				"a v0.93-v0.95.x binary would start on this database and run a pre-#3258 retention purge (#3359) / pre-#3215 resume (#3362)")
			require.False(t, releasedADR101Starts(t, db),
				"a v0.96.x binary would start on this database (recorded floor %v) and run a pre-#3258 retention purge (#3359) / pre-#3215 resume (#3362)",
				func() string { v, _ := releasedMetadata(t, db, schemaMinCompatibleEpochMetadataKey); return v }())
			require.NoError(t, checkSchemaEpochFor(db, currentSchemaEpoch), "this binary must still start")
		})
	}
}
