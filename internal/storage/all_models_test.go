package storage

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestAllModels_MatchesLiveMigratedTables is design-b3-backup-v2.md §3.2's
// own required CI test: AllModels() is a hand-written list (see its doc
// comment for why), so its correctness rests entirely on this test failing
// loudly the moment it drifts from what migrateDatabase actually creates —
// in either direction: a model added to migrateDatabase and forgotten here
// (backup would silently skip a real table), or a stale entry left here
// after a model is removed from migrateDatabase (backup would fail trying to
// read a table that no longer exists).
func TestAllModels_MatchesLiveMigratedTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "all_models_roundtrip.db")
	db, err := gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	// sqliteImplicitTables are tables SQLite itself creates as a side effect of
	// AUTOINCREMENT columns, never a GORM model and never present on Postgres —
	// excluded here, not added to AllModels(), so this test's failure still
	// means what its own doc comment says for every table that actually is one.
	sqliteImplicitTables := map[string]bool{"sqlite_sequence": true}

	liveTables, err := db.Migrator().GetTables()
	require.NoError(t, err)
	liveSet := make(map[string]bool, len(liveTables))
	for _, tn := range liveTables {
		if sqliteImplicitTables[tn] {
			continue
		}
		liveSet[tn] = true
	}

	registryTables := make(map[string]bool, len(AllModels()))
	for _, m := range AllModels() {
		stmt := &gorm.Statement{DB: db}
		require.NoError(t, stmt.Parse(m), "parse %T", m)
		tn := stmt.Schema.Table
		require.False(t, registryTables[tn], "AllModels() lists table %q more than once (via %T)", tn, m)
		registryTables[tn] = true
	}

	var missingFromRegistry []string // migrateDatabase creates it, AllModels() doesn't know about it
	for tn := range liveSet {
		if !registryTables[tn] {
			missingFromRegistry = append(missingFromRegistry, tn)
		}
	}
	var staleInRegistry []string // AllModels() claims it, migrateDatabase never creates it
	for tn := range registryTables {
		if !liveSet[tn] {
			staleInRegistry = append(staleInRegistry, tn)
		}
	}
	sort.Strings(missingFromRegistry)
	sort.Strings(staleInRegistry)

	require.Empty(t, missingFromRegistry,
		"migrateDatabase creates these tables but AllModels() does not list them -- "+
			"a real table would be silently skipped by admin backup; add the missing model(s) to AllModels()")
	require.Empty(t, staleInRegistry,
		"AllModels() lists these tables but migrateDatabase never creates them -- "+
			"admin backup would fail trying to read a table that doesn't exist; remove the stale model(s) from AllModels()")
}
