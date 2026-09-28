// restore_postgres_sequence_resync_test.go is resyncPostgresSequences's own
// proving test (design-b3-backup-v2.md §4/H6): LoadArchive inserts every row
// with its original, explicit primary-key value, exactly like a real v2
// restore does -- Postgres never auto-advances a SERIAL/BIGSERIAL column's
// sequence for an explicit-value INSERT, so without this fixup the very next
// auto-generated INSERT on a restored table collides with an already-
// restored row's id.
package admin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestResyncPostgresSequences_FixesCollisionAfterExplicitIDInserts(t *testing.T) {
	base := pgAdminTestDSN(t)
	dsn := pgAdminIsolatedDatabaseDSN(t, base)
	db := pgAdminRawOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(storage.AllModels()...))

	// Simulate LoadArchive's own row-preserving insert: explicit ids 1..3,
	// matching what a restored table's rows actually look like -- the
	// table's sequence stays at its fresh-migration default (nextval=1)
	// throughout, since none of these went through a value-omitted INSERT.
	for i := 1; i <= 3; i++ {
		require.NoError(t, db.Exec("INSERT INTO projects (id, name) VALUES (?, ?)", i, "restored").Error)
	}

	sqlDB, err := db.DB()
	require.NoError(t, err)

	require.NoError(t, resyncPostgresSequences(sqlDB),
		"resyncPostgresSequences must not fail against a real, freshly-loaded table set")

	require.NoError(t, db.Create(&models.Project{Name: "post-restore"}).Error,
		"an auto-generated insert right after restore must not collide with an already-restored row's id")

	var count int64
	require.NoError(t, db.Model(&models.Project{}).Count(&count).Error)
	require.Equal(t, int64(4), count)

	var maxID uint
	require.NoError(t, db.Model(&models.Project{}).Select("MAX(id)").Scan(&maxID).Error)
	require.Equal(t, uint(4), maxID, "the auto-generated row must have gotten id=4, not collided with 1-3")
}

// TestResyncPostgresSequences_EmptyTableStaysAtOne proves the other half of
// the setval fixup's correctness: a table storage.AllModels() defines but
// this archive happened to have zero rows for (design §8's version-
// skipping-upgrade case) must not have its sequence perturbed away from 1 --
// the three-argument setval's is_called=false branch when MAX(id) is NULL.
func TestResyncPostgresSequences_EmptyTableStaysAtOne(t *testing.T) {
	base := pgAdminTestDSN(t)
	dsn := pgAdminIsolatedDatabaseDSN(t, base)
	db := pgAdminRawOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(storage.AllModels()...))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, resyncPostgresSequences(sqlDB))

	require.NoError(t, db.Create(&models.Project{Name: "first"}).Error)
	var firstID uint
	require.NoError(t, db.Model(&models.Project{}).Select("id").Scan(&firstID).Error)
	require.Equal(t, uint(1), firstID, "an empty table's first auto-generated row must still get id=1")
}
