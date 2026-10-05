package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// TestSQLiteDSN_SynchronousFollowsSkipDurableSync is the unit-level half of
// ADR-112 Amendment 1's SQLite mechanism (FASTAUDIT-1,
// docs/specs/fast-audit-mode.md): FULL unless the operator explicitly asked
// for the fast mode, NORMAL when they did, and every other pragma untouched
// in both cases.
//
// Asserting the OTHER pragmas are unchanged matters as much as the
// synchronous value: this change edits the one format string that carries
// foreign-key enforcement (#436), the busy timeout and WAL mode (#465), and
// BEGIN IMMEDIATE (#1996) too. A refactor that accidentally dropped one of
// those while getting `synchronous` right would be a real regression that a
// synchronous-only assertion would wave through.
func TestSQLiteDSN_SynchronousFollowsSkipDurableSync(t *testing.T) {
	const path = "/data/secrets.db"

	t.Run("default is FULL", func(t *testing.T) {
		dsn := sqliteDSN(path, false)
		require.Contains(t, dsn, "_synchronous=FULL",
			"the DEFAULT must stay FULL: ADR-112 §3's baseline is that a secret value is never returned "+
				"before its audit record is durably committed")
		require.NotContains(t, dsn, "NORMAL")
	})

	t.Run("fast audit mode is NORMAL", func(t *testing.T) {
		dsn := sqliteDSN(path, true)
		require.Contains(t, dsn, "_synchronous=NORMAL",
			"with storage.database.insecure_audit_skip_durable_sync set, the DSN must weaken to NORMAL -- "+
				"otherwise the setting is inert on SQLite and every fast-mode measurement means nothing")
		require.NotContains(t, dsn, "FULL")
	})

	// Everything else is identical either way.
	for _, skip := range []bool{false, true} {
		dsn := sqliteDSN(path, skip)
		for _, want := range []string{"_foreign_keys=1", "_busy_timeout=10000", "_journal_mode=WAL", "_txlock=immediate"} {
			require.Containsf(t, dsn, want,
				"skipDurableSync=%v dropped %q from the DSN -- this setting may only change `synchronous`, "+
					"never foreign-key enforcement (#436), the busy timeout or WAL mode (#465), or BEGIN "+
					"IMMEDIATE (#1996)", skip, want)
		}
	}
}

// TestFastAuditMode_SQLitePragmaFollowsTheSetting is the same property
// end-to-end through the REAL production open path, because a DSN string
// assertion alone does not prove SQLite honoured it. Mirrors
// TestSQLitePragmas_EnabledOnFreshConnection's method exactly (CreateStorage
// to open, then a SECOND independent connection through OpenGormDB to read
// the pragma back) against a temp-FILE-backed database -- never ":memory:",
// where journal_mode=WAL is silently downgraded and so the pragma under test
// would not be exercised at all.
//
// The off case is deliberately duplicated with
// TestSQLitePragmas_EnabledOnFreshConnection. That test is the standing
// baseline guard and must keep passing untouched (it knows nothing about this
// setting); this one asserts the SAME default from the opposite direction --
// that adding an opt-out did not quietly make the opt-out the default.
func TestFastAuditMode_SQLitePragmaFollowsTheSetting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	for _, tc := range []struct {
		name            string
		skipDurableSync bool
		wantSynchronous int // SQLite's own encoding: 2 = FULL, 1 = NORMAL
	}{
		{"default: durable (FULL)", false, 2},
		{"fast audit mode: NORMAL", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Storage.Type = "local"
			cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "fast-audit-pragma.db")
			cfg.Storage.Database.InsecureAuditSkipDurableSync = tc.skipDurableSync

			_, err := NewStorageFactory().CreateStorage(cfg)
			require.NoError(t, err)

			db, err := OpenGormDB(cfg)
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			defer func() { _ = sqlDB.Close() }()

			var synchronous int
			require.NoError(t, sqlDB.QueryRow("PRAGMA synchronous").Scan(&synchronous))
			require.Equalf(t, tc.wantSynchronous, synchronous,
				"PRAGMA synchronous = %d, want %d. With insecure_audit_skip_durable_sync=%v the live "+
					"connection must report %s -- and note this is asserted on a SECOND connection opened "+
					"through OpenGormDB, so it proves the value is a property of every connection this "+
					"codebase opens against the configured path, not a one-off inside CreateStorage.",
				synchronous, tc.wantSynchronous, tc.skipDurableSync,
				map[int]string{1: "NORMAL (1)", 2: "FULL (2)"}[tc.wantSynchronous])

			// WAL mode is a precondition of the whole safety argument, not a
			// detail: SQLite's "safe from corruption with synchronous=NORMAL"
			// guarantee is stated for WAL mode specifically. If the fast mode
			// ever ended up on a rollback journal, NORMAL would no longer carry
			// that guarantee and the lost-tail-never-a-gap claim would be
			// unsupported.
			var journalMode string
			require.NoError(t, sqlDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode))
			require.Equal(t, "wal", journalMode,
				"journal_mode must still be WAL: SQLite's no-corruption-at-NORMAL guarantee is specific to "+
					"WAL mode, so the fast audit mode's safety argument depends on it")
		})
	}
}
