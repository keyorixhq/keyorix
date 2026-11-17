package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// #4091: BreakGlassActivation.ReviewedBy gained `gorm:"index"` in the v0.96
// line, but an existing break_glass_activations table only gets the column
// (createBreakGlassActivations' AddColumn loop), so a database installed
// before v0.96 never had idx_break_glass_activations_reviewed_by. The upgrade
// path now creates it, and running the migration again changes nothing.
func testBreakGlassReviewedByIndexOnUpgrade(t *testing.T, db *gorm.DB) {
	const idx = "idx_break_glass_activations_reviewed_by"
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.True(t, indexExists(db, idx), "a fresh install has the index (AutoMigrate)")
	fresh := indexDefinition(db, idx)

	// A pre-v0.96 install: the table and column exist, the index does not.
	require.NoError(t, db.Exec("DROP INDEX "+idx).Error)
	require.False(t, indexExists(db, idx))

	require.NoError(t, f.migrateDatabase(db))
	require.True(t, indexExists(db, idx), "the upgrade path must create the index")
	upgraded := indexDefinition(db, idx)
	if db.Dialector.Name() == "postgres" {
		// Same definition as a fresh install (the oracle compares pg_indexes).
		assert.Equal(t, fresh, upgraded)
	} else {
		assert.Contains(t, upgraded, "reviewed_by")
	}

	require.NoError(t, f.migrateDatabase(db), "a second run is a no-op")
	assert.Equal(t, upgraded, indexDefinition(db, idx))
}

func TestBreakGlassReviewedByIndex_CreatedOnUpgrade(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bg-reviewed-by.db"))
	require.NoError(t, err)
	testBreakGlassReviewedByIndexOnUpgrade(t, db)
}

func TestBreakGlassReviewedByIndex_CreatedOnUpgrade_Postgres(t *testing.T) {
	testBreakGlassReviewedByIndexOnUpgrade(t, pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t))))
}
