// upgrade_pg_redproof_test.go -- one harness-side break per oracle of
// upgrade_pg_fuzz_test.go, each asserting that exact oracle fires, with a clean
// baseline as the control. No production code is altered: every break edits only
// the scratch database of that one run.
//
// Also the v0.91.0 interrupted-upgrade comparison: the SQLite leg's bare-path
// artefact (TestUpgradeInterrupted_V091_BarePathArtefact) re-checked on
// PostgreSQL, through the real locked path and through the bare migrateDatabase
// path.
package storage

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

func TestUpgradePGOracles_RedProof(t *testing.T) {
	const tag = "v0.95.3"

	t.Run("green_baseline", func(t *testing.T) {
		if f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{}); len(f) != 0 {
			t.Fatalf("baseline must be clean, got %v", f)
		}
	})

	t.Run("invariant1_corrupted_ciphertext", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, `UPDATE secret_versions SET encrypted_value = '\x00112233445566778899aabbccddeeff00112233'::bytea WHERE secret_node_id = 1 AND version_number = 1`)
		}})
		ugAssertFires(t, f, 1)
	})

	t.Run("invariant1_snapshot_ciphertext_swap_before_upgrade", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterGenerate: func(db *sql.DB) error {
			return ugExecStmts(db,
				"UPDATE secret_versions SET encrypted_value = (SELECT encrypted_value FROM secret_versions WHERE secret_node_id = 2 AND version_number = 1) WHERE secret_node_id = 3 AND version_number = 1",
			)
		}})
		ugAssertFires(t, f, 1)
	})

	t.Run("invariant2_dropped_grant_after_migration", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DELETE FROM user_roles WHERE user_id = 2")
		}})
		ugAssertFires(t, f, 2)
	})

	t.Run("invariant2_widened_scope_after_migration", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE user_roles SET project_id = 0, environment_id = 0 WHERE user_id = 2")
		}})
		ugAssertFires(t, f, 2)
	})

	t.Run("invariant3_lost_audit_row", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DELETE FROM audit_events WHERE id = (SELECT MIN(id) FROM audit_events)")
		}})
		ugAssertFires(t, f, 3)
	})

	t.Run("invariant3_tampered_audit_row_breaks_chain", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE audit_events SET description = 'rewritten' WHERE id = (SELECT MIN(id) FROM audit_events)")
		}})
		ugAssertFires(t, f, 3)
	})

	t.Run("invariant4_change_during_second_migration", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{beforeRerun: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE projects SET description = 'rerun changed me' WHERE id = 1")
		}})
		ugAssertFires(t, f, 4)
	})

	t.Run("invariant7_changed_default_and_type", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "ALTER TABLE projects ALTER COLUMN description SET DEFAULT 'changed'")
		}})
		ugAssertFires(t, f, 7)
	})

	t.Run("invariant8_dropped_index", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DROP INDEX uniq_secret_nodes_project_env_name_active")
		}})
		ugAssertFires(t, f, 8)
	})

	t.Run("invariant8_dropped_constraint", func(t *testing.T) {
		f := pgRun(t, tag, true, ugRedSeed, 0, pgHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "ALTER TABLE secret_versions DROP CONSTRAINT secret_versions_pkey")
		}})
		ugAssertFires(t, f, 8)
	})
}

// TestUpgradePGInterrupted_AtomicityOracle_RedProof: oracle 6 fires when the same
// stop runs without the transaction the real path provides, and stays silent on
// the real path, on the same state and the same statement.
func TestUpgradePGInterrupted_AtomicityOracle_RedProof(t *testing.T) {
	const tag, stop = "v0.91.0", 60

	bare := pgRun(t, tag, false, ugRedSeed, stop, pgHooks{bareInterrupt: true})
	ugAssertFires(t, bare, 6)

	real := pgRun(t, tag, false, ugRedSeed, stop, pgHooks{})
	for _, f := range real {
		if f.Invariant == 6 {
			t.Fatalf("the real path must leave the database untouched, got: %v", f.Detail)
		}
	}
	t.Logf("real path findings at stop=%d: %v", stop, real)
}

// TestUpgradeInterrupted_V091_SQLite_RealPath: the SQLite artefact
// TestUpgradeInterrupted_V091_BarePathArtefact records was reached by calling
// migrateDatabase directly, outside withMigrationLock's BEGIN EXCLUSIVE. This
// test takes the real path at three stops with its own callbacks, independent of
// the fuzz harness's ugInterruptedMigrate.
func TestUpgradeInterrupted_V091_SQLite_RealPath(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	tpl, err := ugLoadTemplate("v0.91.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, stop := range []int{34, 41, 200} {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "upgrade.db")
		if err := ugCopyFile(tpl.dbFile, dbPath); err != nil {
			t.Fatal(err)
		}
		gdb, err := openSQLiteGorm(sqliteDSN(dbPath))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := gdb.DB()
		if err != nil {
			t.Fatal(err)
		}
		seen := pgRegisterStop(t, gdb, stop)
		f := &DefaultStorageFactory{}
		mErr := withMigrationLock(gdb, false, dbPath, f.migrateSQLite)
		_ = raw.Close()
		if seen.Load() < int64(stop) || !errors.Is(mErr, errPGInterrupted) {
			t.Fatalf("stop=%d was not reached (saw %d statements, migration returned %v): nothing was interrupted", stop, seen.Load(), mErr)
		}

		st, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
		if err != nil {
			t.Fatalf("stop=%d: restart failed: %v", stop, err)
		}
		c := core.NewKeyorixCore(st)
		c.SetAuthEncryptor(tpl.enc)
		c.SetSecretValueEncryptor(tpl.enc)
		if _, err := c.GetSecretValue(t.Context(), 1); err != nil {
			_ = ugCloseStorage(st)
			t.Fatalf("stop=%d: real-path interrupted upgrade left secrets unreadable: %v", stop, err)
		}
		_ = ugCloseStorage(st)
	}
}

// TestUpgradePGInterrupted_V091_Compare records what the SQLite leg's defect
// looks like on PostgreSQL on both paths.
func TestUpgradePGInterrupted_V091_Compare(t *testing.T) {
	for _, stop := range []int{34, 41, 60, 200} {
		t.Run("real_path", func(t *testing.T) {
			f := pgRun(t, "v0.91.0", false, nil, stop, pgHooks{})
			t.Logf("real path stop=%d findings: %v", stop, f)
			if len(f) != 0 {
				t.Errorf("real path must complete cleanly on restart, stop=%d: %v", stop, f)
			}
		})
		t.Run("bare_shape", func(t *testing.T) {
			f := pgRun(t, "v0.91.0", false, nil, stop, pgHooks{bareInterrupt: true})
			t.Logf("bare migrateDatabase shape stop=%d findings: %v", stop, f)
		})
	}
}
