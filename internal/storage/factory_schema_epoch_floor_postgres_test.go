// factory_schema_epoch_floor_postgres_test.go — the real-Postgres
// counterpart to factory_schema_epoch_floor_test.go (INV-STORAGE-04, #2502):
// recordSchemaEpochAs's raise-only upsert is dialect-specific SQL
// (ON CONFLICT ... CASE WHEN CAST(...)), so it is proven on both dialects.
// Gated on KEYORIX_TEST_PG_DSN so `go test ./...` still passes cleanly with
// no Postgres available.
package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaEpochFloor_Postgres_RecordAndRefuse(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)
	db := pgRawOpen(t, dsn)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	assert.Equal(t, "1", readEpochRow(t, db, schemaEpochMetadataKey))
	assert.Equal(t, "1", readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))

	// Additive-safe newer epoch: floor unchanged, this binary still boots
	// and does not stamp the epoch back down.
	require.NoError(t, recordSchemaEpochAs(db, 2, 1))
	require.NoError(t, f.migrateDatabase(db))
	assert.Equal(t, "2", readEpochRow(t, db, schemaEpochMetadataKey))
	assert.Equal(t, "1", readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))

	// Breaking newer epoch: floor raised above this binary -- refuse.
	require.NoError(t, recordSchemaEpochAs(db, 3, 3))
	require.NoError(t, recordSchemaEpochAs(db, 1, 1), "an older record must be a no-op, not an error")
	assert.Equal(t, "3", readEpochRow(t, db, schemaEpochMetadataKey))
	assert.Equal(t, "3", readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))
	err := f.migrateDatabase(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minimum compatible schema epoch of 3")
}
