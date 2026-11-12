// upgrade_old_schema_redproof_test.go -- one harness-side break per oracle of
// upgrade_old_schema_fuzz_test.go, each asserting that exact oracle fires, plus
// the v0.91.0 interrupted-upgrade finding. No production code is altered: every
// break edits only the scratch database of that one run.
package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
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

	t.Run("invariant4_change_during_second_migration", func(t *testing.T) {
		// A step that is not idempotent looks like this from outside: the bytes after
		// a re-run differ from the bytes before it.
		f := ugRun(t, tag, true, ugRedSeed, 0, ugHooks{beforeRerun: func(db *sql.DB) error {
			return ugExecStmts(db, "UPDATE projects SET description = 'rerun changed me' WHERE id = 1")
		}})
		ugAssertFires(t, f, 4)
	})
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
//
// It asserts both halves: the bare path still fires (so the real path's
// silence is not vacuous) and the real path, same source and same stop, is clean.
func TestUpgradeInterrupted_V091_BarePathArtefact(t *testing.T) {
	const tag, stop = "v0.91.0", 41

	bare := ugRun(t, tag, false, nil, stop, ugHooks{bareInterrupt: true})
	var sawSecretRead bool
	for _, f := range bare {
		if f.Invariant == 1 && strings.Contains(f.Detail, "owner_machine_identity_id") {
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
