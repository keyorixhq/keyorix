package storage

// migrate_postgres_nonpublic_schema_test.go — regression for #1980.
//
// migrateDatabase's Postgres existence checks (tableExists, columnExists,
// indexExists, rolePKIsComplete, guardAccountStateValid's constraint lookups)
// used to hard-code table_schema='public' or ignore the schema entirely, so a
// database migrated through a connection whose current_schema() is NOT public
// silently skipped every tableExists-gated index/constraint — including
// uniq_secret_versions_node_version (#121's backstop). This migrates one
// fresh database in its default public schema and another into a non-public
// schema via search_path, then asserts both end up with the same set of
// indexes and constraints.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

func migrateViaFactory(t *testing.T, dsn string) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	require.NotNil(t, st)
	// Second boot must be an idempotent no-op in either schema.
	_, err = NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "re-running the migration must be idempotent")
}

// schemaObjects returns the sorted index and constraint names in schema.
func schemaObjects(t *testing.T, db *gorm.DB, schema string) (indexes, constraints []string) {
	t.Helper()
	require.NoError(t, db.Raw("SELECT indexname FROM pg_indexes WHERE schemaname = ?", schema).Scan(&indexes).Error)
	require.NoError(t, db.Raw("SELECT constraint_name FROM information_schema.table_constraints WHERE table_schema = ? AND constraint_type IN ('PRIMARY KEY','UNIQUE','CHECK','FOREIGN KEY') AND constraint_name NOT LIKE '%_not_null'", schema).Scan(&constraints).Error)
	sort.Strings(indexes)
	sort.Strings(constraints)
	return indexes, constraints
}

func TestMigrateDatabase_Postgres_NonPublicSchemaMatchesPublic(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	base := pgTestDSN(t)

	// Reference: default public-schema migration.
	pubDSN := pgIsolatedDatabaseDSN(t, base)
	migrateViaFactory(t, pubDSN)
	pubIdx, pubCons := schemaObjects(t, pgRawOpen(t, pubDSN), "public")
	require.Contains(t, pubIdx, "uniq_secret_versions_node_version", "sanity: the public migration creates the #121 backstop index")

	// Same migration into a non-public schema. The public schema of this
	// database is pre-seeded with a same-named decoy index so an unscoped
	// indexExists would wrongly report it present and skip creating it.
	appDSN := pgIsolatedDatabaseDSN(t, base)
	admin := pgRawOpen(t, appDSN)
	require.NoError(t, admin.Exec("CREATE SCHEMA kx_app").Error)
	require.NoError(t, admin.Exec("CREATE TABLE public.decoy (a int, b int)").Error)
	require.NoError(t, admin.Exec("CREATE UNIQUE INDEX uniq_secret_versions_node_version ON public.decoy (a, b)").Error)
	migrateViaFactory(t, pgdsn.PGSearchPathDSN(appDSN, "kx_app"))
	appIdx, appCons := schemaObjects(t, admin, "kx_app")

	assert.Equal(t, pubIdx, appIdx, "a non-public-schema migration must create exactly the indexes a public one does")
	assert.Equal(t, pubCons, appCons, "a non-public-schema migration must create exactly the constraints a public one does")

	var publicTables int64
	require.NoError(t, admin.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name <> 'decoy'").Scan(&publicTables).Error)
	assert.Zero(t, publicTables, "nothing may be created in public when current_schema() is kx_app")
}
