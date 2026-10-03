// factory_schema_epoch_corrupt_test.go — INV-STORAGE-03 (#2501): a corrupt
// (non-integer) schema_epoch in system_metadata must fail closed at boot.
//
// TestSchemaEpoch_CorruptRecordedEpoch_FailsClosed (factory_schema_epoch_test.go)
// already covers one shape, "not-a-number", through migrateDatabase. This file
// closes two gaps that test leaves open:
//
//  1. Value shapes. "not-a-number" is rejected by every plausible parser, so
//     that test stays green if checkSchemaEpoch's strict strconv.Atoi is ever
//     swapped for a lenient one -- fmt.Sscanf("%d") reads "1abc" as 1 with no
//     error, strings.TrimSpace+Atoi accepts " 1", ParseFloat accepts "1.0".
//     Each of those would silently treat a corrupted marker as a valid,
//     in-range epoch and let migrations run. The cases below are chosen so at
//     least one goes red under each of those substitutions.
//  2. The boot path. That test calls migrateDatabase directly; this one also
//     drives the real NewStorageFactory().CreateStorage entry point, so the
//     claim "refuses boot" is asserted at the layer that makes it, and checks
//     the refusal leaves the database untouched (no migration step ran, the
//     corrupt marker was not "repaired" over by recordSchemaEpoch).
//
// What this does NOT cover: Postgres (checkSchemaEpoch is dialect-agnostic
// past tableExists, which has its own coverage), and a value that parses as
// an integer but is semantically wrong (e.g. "0" or "-1" -- those are an
// older epoch and legitimately proceed; see
// TestSchemaEpoch_OlderRecordedEpoch_UpgradeSucceeds).
package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corruptSchemaEpochValues are values a lenient parser could plausibly accept
// as a valid, in-range epoch. Every one must be refused.
var corruptSchemaEpochValues = []struct {
	name, value string
}{
	{"non-numeric", "not-a-number"},
	{"empty", ""},
	{"numeric prefix then garbage", "1abc"}, // fmt.Sscanf("%d") -> 1, nil
	{"leading whitespace", " 1"},            // strings.TrimSpace+Atoi -> 1
	{"trailing newline", "1\n"},             // strings.TrimSpace+Atoi -> 1
	{"decimal", "1.0"},                      // strconv.ParseFloat -> 1
	{"hex", "0x1"},                          // strconv.ParseInt(s, 0, 0) -> 1
	{"overflow", "99999999999999999999999"}, // must not wrap to a small epoch
}

// seedSchemaEpoch creates system_metadata and records value as schema_epoch
// in a fresh SQLite file at path.
func seedSchemaEpoch(t *testing.T, path, value string) {
	t.Helper()
	db, err := gormOpenForTest(t, path)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: value}).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

// assertRefusedUntouched reopens path and asserts the refused boot neither
// ran a later migration step nor overwrote the corrupt marker.
func assertRefusedUntouched(t *testing.T, path, value string) {
	t.Helper()
	db, err := gormOpenForTest(t, path)
	require.NoError(t, err)
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	assert.False(t, tableExists(db, "users"),
		"a refused boot must short-circuit before any other migration step creates tables")
	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
	assert.Equal(t, value, m.Value,
		"the corrupt marker must be left in place for an operator to inspect, not overwritten by recordSchemaEpoch")
}

func TestSchemaEpoch_CorruptValueShapes_MigrateDatabaseRefuses(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	for _, tc := range corruptSchemaEpochValues {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "epoch-corrupt.db")
			seedSchemaEpoch(t, path, tc.value)

			db, err := gormOpenForTest(t, path)
			require.NoError(t, err)
			err = (&DefaultStorageFactory{}).migrateDatabase(db)
			if sqlDB, derr := db.DB(); derr == nil {
				_ = sqlDB.Close()
			}
			require.Error(t, err, "schema_epoch %q must fail closed", tc.value)
			assert.Contains(t, err.Error(), "not a valid integer")
			assertRefusedUntouched(t, path, tc.value)
		})
	}
}

func TestSchemaEpoch_CorruptValue_CreateStorageRefusesBoot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	for _, tc := range corruptSchemaEpochValues {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "epoch-corrupt-boot.db")
			seedSchemaEpoch(t, path, tc.value)

			cfg := &config.Config{}
			cfg.Storage.Type = "local"
			cfg.Storage.Database.Path = path
			st, err := NewStorageFactory().CreateStorage(cfg)
			require.Error(t, err, "booting against schema_epoch %q must be refused", tc.value)
			assert.Nil(t, st)
			assert.Contains(t, err.Error(), "not a valid integer")
			assertRefusedUntouched(t, path, tc.value)
		})
	}
}
