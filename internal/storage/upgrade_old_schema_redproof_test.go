// upgrade_old_schema_redproof_test.go -- one harness-side break per oracle of
// upgrade_old_schema_fuzz_test.go, each asserting that exact oracle fires, plus
// the v0.91.0 interrupted-upgrade finding. No production code is altered: every
// break edits only the scratch database of that one run.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"
)

var ugRedSeed = []byte{1, 0, 1, 2, 0, 3, 1, 2, 1, 1, 0, 2, 3, 3, 2, 1, 0, 1, 2, 3, 1, 1, 2, 0, 3, 4, 5, 1, 2, 2, 1, 7, 9}

func ugExecStmts(db *sql.DB, stmts ...string) error {
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// ugAssertFires requires at least one finding for invariant and returns it.
func ugAssertFires(t *testing.T, findings []ugFinding, invariant int) ugFinding {
	t.Helper()
	for _, f := range findings {
		if f.Invariant == invariant {
			t.Logf("oracle %d fired: %s", invariant, f.Detail)
			return f
		}
	}
	t.Fatalf("oracle %d did not fire; findings: %v", invariant, findings)
	return ugFinding{}
}

func TestUpgradeOracles_RedProof(t *testing.T) {
	const tag = "v0.95.3"

	t.Run("green_baseline_v0.95.3", func(t *testing.T) {
		if f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{}); len(f) != 0 {
			t.Fatalf("baseline must be clean, got %v", f)
		}
	})

	t.Run("invariant1_corrupted_ciphertext", func(t *testing.T) {
		// A re-encryption that was dropped or mangled reads exactly like this:
		// the row exists, its metadata still claims AES-GCM, the bytes are wrong.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE secret_versions SET encrypted_value = X'00112233445566778899aabbccddeeff00112233' WHERE secret_node_id = 1 AND version_number = 1")
		}})
		ugAssertFires(t, f, 1)
	})

	t.Run("invariant1_snapshot_ciphertext_swap_before_upgrade", func(t *testing.T) {
		// The same fault in the old database itself (a deliberately corrupted snapshot):
		// two rows of the same secret traded ciphertexts, so the AAD no longer matches.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterGenerate: func(db *sql.DB) error {
			return ugExecStmts(db,
				"UPDATE secret_versions SET encrypted_value = (SELECT encrypted_value FROM secret_versions WHERE secret_node_id = 2 AND version_number = 1) WHERE secret_node_id = 3 AND version_number = 1",
			)
		}})
		ugAssertFires(t, f, 1)
	})

	t.Run("invariant2_dropped_grant_after_migration", func(t *testing.T) {
		// The role grant rows a rebuildRolePK that lost rows would leave behind.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DELETE FROM user_roles WHERE user_id = 2")
		}})
		ugAssertFires(t, f, 2)
	})

	t.Run("invariant2_widened_scope_after_migration", func(t *testing.T) {
		// The upgrade must not widen access: project-scoped grant becomes global.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE user_roles SET project_id = 0, environment_id = 0 WHERE user_id = 2")
		}})
		ugAssertFires(t, f, 2)
	})

	t.Run("invariant3_lost_audit_row", func(t *testing.T) {
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DELETE FROM audit_events WHERE id = (SELECT MIN(id) FROM audit_events)")
		}})
		ugAssertFires(t, f, 3)
	})

	t.Run("invariant3_tampered_audit_row_breaks_chain", func(t *testing.T) {
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE audit_events SET description = 'rewritten' WHERE id = (SELECT MIN(id) FROM audit_events)")
		}})
		found := ugAssertFires(t, f, 3)
		if !strings.Contains(found.Detail, "chain") {
			t.Fatalf("expected the chain verifier, not the row count, to fire: %s", found.Detail)
		}
	})

	t.Run("invariant4_control_shimmed_rerun_without_the_step", func(t *testing.T) {
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{rerunShim: func(t testing.TB, dbPath string) {
			ugMigrateWithPlantedStep(t, dbPath, "")
		}})
		if len(f) != 0 {
			t.Fatalf("the shim itself must not change the database, got %v", f)
		}
	})

	t.Run("invariant4_non_idempotent_step_in_a_real_migration", func(t *testing.T) {
		// A backfill with no already-done gate: it runs inside the real step list on
		// every boot and appends each time.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{rerunShim: func(t testing.TB, dbPath string) {
			ugMigrateWithPlantedStep(t, dbPath, "UPDATE projects SET description = description || ' (backfilled)' WHERE id = 1")
		}})
		found := ugAssertFires(t, f, 4)
		if !strings.Contains(found.Detail, "(backfilled)") {
			t.Fatalf("expected the planted step's own change to be what fired: %s", found.Detail)
		}
	})

	t.Run("invariant6_upgrade_missing_an_index", func(t *testing.T) {
		// What a model index no step creates on an existing table looks like.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DROP INDEX idx_secret_nodes_classification")
		}})
		found := ugAssertFires(t, f, 6)
		if !strings.Contains(found.Detail, "only in fresh: index secret_nodes.idx_secret_nodes_classification") {
			t.Fatalf("expected the dropped index to be named: %s", found.Detail)
		}
	})

	t.Run("invariant6_upgrade_changed_a_column_type", func(t *testing.T) {
		// The wrong type for a column that exists: SQLite accepts any type name, and
		// the fresh-install side names the right one.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db,
				"ALTER TABLE projects RENAME COLUMN require_mfa TO require_mfa_old",
				"ALTER TABLE projects ADD COLUMN require_mfa TIMESTAMP WITH TIME ZONE",
			)
		}})
		found := ugAssertFires(t, f, 6)
		if !strings.Contains(found.Detail, "projects.require_mfa") {
			t.Fatalf("expected the changed column to be named: %s", found.Detail)
		}
	})

	t.Run("invariant6_expected_difference_disappears", func(t *testing.T) {
		// Someone fixes a listed difference and leaves its entry behind.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "CREATE INDEX idx_break_glass_activations_reviewed_by ON break_glass_activations (reviewed_by)")
		}})
		found := ugAssertFires(t, f, 6)
		if !strings.Contains(found.Detail, "no longer occurs") || !strings.Contains(found.Detail, "ugExpectedSchemaDiffs") {
			t.Fatalf("expected the stale-entry finding: %s", found.Detail)
		}
	})

	t.Run("invariant5_control_restart_after_a_stop_is_clean", func(t *testing.T) {
		if f := ugRun(t, tag, true, ugRedSeed, ugRedStop, ugHooks{}); len(f) != 0 {
			t.Fatalf("a stop the restart can recover from must be clean, got %v", f)
		}
	})

	t.Run("invariant5_index_lost_outside_the_known_gaps", func(t *testing.T) {
		// ugStopWindowDiffs tolerates exact lines only: another lost index still fires.
		f := ugRun(t, tag, true, ugRedSeed, ugRedStop, ugHooks{afterMigrate: func(db *sql.DB) error {
			return ugExecStmts(db, "DROP INDEX idx_secret_nodes_classification")
		}})
		found := ugAssertFires(t, f, 5)
		if !strings.Contains(found.Detail, "oracle 6") {
			t.Fatalf("expected the schema oracle: %s", found.Detail)
		}
	})

	t.Run("invariant5_step_leaves_a_half_state", func(t *testing.T) {
		// A step that rebuilds a table by moving it aside first, without a
		// transaction around the move and the rebuild: the crash leaves the table
		// gone and its rows under another name, and no step looks there.
		f := ugRun(t, tag, true, ugRedSeed, ugRedStop, ugHooks{halfStateAtStop: func(db *sql.DB) error {
			return ugExecStmts(db, "ALTER TABLE user_roles RENAME TO user_roles_rebuild")
		}})
		ugAssertFires(t, f, 5)
	})
}

// ugPlantStepAfter is a statement of the real step list that runs on every boot.
const ugPlantStepAfter = "idx_secret_nodes_classification"

// ugMigrateWithPlantedStep runs the real migrateDatabase with one extra statement
// executed right after ugPlantStepAfter, as a step of that list would be. An empty
// plant still runs the shim, for the control. The anchor must be hit, or the test
// would silently stop planting anything once that step changes.
func ugMigrateWithPlantedStep(t testing.TB, dbPath, plant string) {
	t.Helper()
	gdb, err := openSQLiteGorm(sqliteDSN(dbPath))
	if err != nil {
		t.Fatalf("opening %s: %v", dbPath, err)
	}
	raw, err := gdb.DB()
	if err != nil {
		t.Fatalf("raw handle: %v", err)
	}
	defer func() { _ = raw.Close() }()
	var planted atomic.Bool
	err = gdb.Callback().Raw().After("gorm:raw").Register("ug:plant_step", func(db *gorm.DB) {
		if db.Error != nil || !strings.Contains(db.Statement.SQL.String(), ugPlantStepAfter) || !planted.CompareAndSwap(false, true) {
			return
		}
		if plant != "" {
			_ = db.AddError(db.Session(&gorm.Session{NewDB: true}).Exec(plant).Error)
		}
	})
	if err != nil {
		t.Fatalf("registering the planted step: %v", err)
	}
	if err := (&DefaultStorageFactory{}).migrateDatabase(gdb); err != nil {
		t.Fatalf("migration with the planted step: %v", err)
	}
	if !planted.Load() {
		t.Fatalf("no statement mentioned %s: the anchor of the planted step is gone", ugPlantStepAfter)
	}
}

// ugRedStop is a stop every source's upgrade reaches: the snapshot's own early
// steps issue more writes than this.
const ugRedStop = 5

// TestUpgradeInterrupted_StopThatNeverFiresIsNotAPass pins the seam's report:
// a stop past the last write says so, and ugRun skips rather than passes.
func TestUpgradeInterrupted_StopThatNeverFiresIsNotAPass(t *testing.T) {
	const tag = "v0.96.3"
	tpl, err := ugLoadTemplate(tag)
	if err != nil {
		t.Fatal(err)
	}
	outcomeAt := func(stop int) ugStopOutcome {
		t.Helper()
		dbPath := filepath.Join(t.TempDir(), "seam.db")
		if err := os.WriteFile(dbPath, tpl.image, 0o600); err != nil {
			t.Fatal(err)
		}
		outcome, err := ugInterruptedMigrate(t, dbPath, stop)
		if err != nil {
			t.Fatal(err)
		}
		return outcome
	}

	if o := outcomeAt(ugRedStop); !o.Fired || !errors.Is(o.Err, errUgInterrupted) {
		t.Fatalf("a reachable stop must fire and surface the injected crash, got %+v", o)
	}
	if o := outcomeAt(math.MaxInt32); o.Fired || o.Err != nil {
		t.Fatalf("a stop past the last write must report that it never fired, got %+v", o)
	}

	var sub *testing.T
	t.Run("skips", func(t *testing.T) {
		sub = t
		ugRun(t, tag, true, nil, math.MaxInt32, ugHooks{})
		t.Fatal("ugRun went on as if the upgrade had been interrupted")
	})
	if !sub.Skipped() {
		t.Fatal("a run whose stop never fired must be skipped, not passed")
	}
}

// TestUpgradeInterrupted_V091_BarePathArtefact is the red-proof for
// FuzzUpgradeInterrupted's real-path interruption, and records why v0.91.0 is
// not exempted from it. A v0.91.0 upgrade stopped after the MFA step-up table
// is created, on the bare path (migrateDatabase on an autocommit connection, no
// withMigrationLock), keeps that table but never gets
// secret_nodes.owner_machine_identity_id: the fresh-install tail that adds it is
// gated on the table's absence, so the restart returns early and every secret
// read fails. No production boot takes the bare path: createLocalStorage runs
// the migration inside withMigrationLock's one BEGIN EXCLUSIVE transaction, so
// the same stop rolls the table back too. The bare result is an artefact of the
// harness shape, not a production defect; see
// docs/findings/2026-11-09-FINDING-v091-interrupted-upgrade-artifact.md.
// TestUpgradeInterrupted_KnownIndexGaps_StillOpen pins ugStopWindowDiffs, the
// tolerated post-stop lines: each row must still show its missing index. It goes
// red when one is fixed, and the row then has to go.
func TestUpgradeInterrupted_KnownIndexGaps_StillOpen(t *testing.T) {
	tpl, err := ugLoadTemplate(ugStopWindowSource)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := ugFreshSchema()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range ugStopWindowDiffs {
		t.Run(row.Stop, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "gap.db")
			if err := os.WriteFile(dbPath, tpl.image, 0o600); err != nil {
				t.Fatal(err)
			}
			outcome, err := ugInterruptedMigrateWhen(t, dbPath, func(_ int64, stmt string) bool { return strings.Contains(stmt, row.Stop) })
			if err != nil {
				t.Fatal(err)
			}
			if !outcome.Fired {
				t.Fatalf("no statement of the upgrade from %s mentions %s; update ugStopWindowDiffs", ugStopWindowSource, row.Stop)
			}
			st, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
			if err != nil {
				t.Fatalf("restart after a stop at %s: %v", row.Stop, err)
			}
			if err := ugCloseStorage(st); err != nil {
				t.Fatal(err)
			}
			raw, _, closeRaw := ugOpenRaw(t, dbPath)
			defer closeRaw()
			got, err := ugSchemaOf(raw)
			if err != nil {
				t.Fatal(err)
			}
			diff := ugSchemaDiff(fresh, got)
			for _, line := range row.Lines {
				if !slices.Contains(diff, line) {
					t.Errorf("known index gap no longer occurs after a stop at %s on %s; remove the row from ugStopWindowDiffs: %s", row.Stop, ugStopWindowSource, line)
				}
			}
		})
	}
}

// TestUpgradeInterrupted_V091_ColumnNeverAdded pins an open finding and doubles
// as the red-proof for FuzzUpgradeInterrupted: a v0.91.0 upgrade stopped after
// the MFA step-up table is created, then restarted, reports success but leaves
// secret_nodes without owner_machine_identity_id, so every secret read fails.
// No step adds that column on an existing database; the fresh-install tail only
// reached it on the first boot because the table's absence kept
// freshInstallComplete false, and the restart sees the table and returns early.
//
// It asserts both halves: the bare path still fires (so the real path's
// silence is not vacuous) and the real path, same source and same stop, is clean.
func TestUpgradeInterrupted_V091_BarePathArtefact(t *testing.T) {
	const tag, stop = "v0.91.0", 41

	bare := ugRun(t, tag, false, nil, stop, ugHooks{bareInterrupt: true})
	var sawSecretRead bool
	for _, f := range bare {
		if f.Invariant == 1 && strings.Contains(f.Detail, "owner_machine_identity_id") {
	for _, f := range findings {
		if f.Invariant == 5 && strings.Contains(f.Detail, "oracle 1") && strings.Contains(f.Detail, "owner_machine_identity_id") {
			sawSecretRead = true
		}
	}
	if !sawSecretRead {
		t.Fatalf("the bare-path interruption no longer reproduces the artefact, so the real-path comparison proves nothing; update the harness. Findings: %v", bare)
	}

	if f := ugRun(t, tag, false, nil, stop, ugHooks{}); len(f) != 0 {
		t.Fatalf("real-path interrupted v0.91.0 upgrade must recover cleanly, got %v", f)
	}
	if f := ugRun(t, tag, false, nil, 0, ugHooks{}); len(f) != 0 {
		t.Fatalf("uninterrupted v0.91.0 upgrade must be clean, got %v", f)
	}
}
