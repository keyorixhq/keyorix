// upgrade_pg_swallowed_redproof_test.go -- oracle 6 of upgrade_pg_fuzz_test.go
// must still fire when a migration fails part way, swallows the error and
// commits. pgInterruptedMigrate treats a nil return as a finished upgrade only
// when the stop hit the ignored final pg_advisory_unlock (keyorixhq/fuzz-corpus#182);
// this guards that the exception stays that narrow.
package storage

import "testing"

func TestUpgradePGInterrupted_SwallowedFailureStillFires(t *testing.T) {
	const tag, stop = "v0.91.0", 60

	t.Run("locked_path", func(t *testing.T) {
		ugAssertFires(t, pgRun(t, tag, false, ugRedSeed, stop, pgHooks{swallowMigrationError: true}), 6)
	})
	t.Run("bare_path", func(t *testing.T) {
		ugAssertFires(t, pgRun(t, tag, false, ugRedSeed, stop, pgHooks{bareInterrupt: true, swallowMigrationError: true}), 6)
	})
}
