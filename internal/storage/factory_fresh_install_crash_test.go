// factory_fresh_install_crash_test.go — crash-consistency coverage for
// migrateDatabase's fresh-install-only bulk AutoMigrate loop (SESSION-FI AT1
// area 8 / #2340 harness reuse).
//
// On SQLite, that loop runs outside any transaction: each db.AutoMigrate call
// auto-commits independently. If the process is interrupted partway through —
// after models.Project's table exists but before a later model's table does —
// the NEXT boot's migrateDatabase call re-checks tableExists(db, "projects"),
// finds it true, and takes the `if projectsExists { return nil }` early
// return BEFORE ever reaching the loop again. The remaining tables are then
// permanently never created: the server boots "successfully" and only fails
// later, at runtime, with "no such table" on anything touching the missed
// model.
//
// This uses the same nil-in-production checkpoint/panic-recover seam as
// internal/encryption's rotationCheckpoint (reused per the task brief's
// pointer to the #2340/AT2 harness): migrationCheckpoint is invoked after
// each model in the loop, a test installs a function that panics at a chosen
// label to simulate an abrupt crash, and a deferred recover swallows only
// that sentinel.
package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// migrationCrash is the sentinel a simulated crash panics with, so the
// harness can tell its own injected crash apart from a genuine panic in the
// code under test.
type migrationCrash struct{ label string }

// runMigrateWithCrash runs migrateDatabase, arming migrationCheckpoint to
// panic (simulating an abrupt process crash) the moment the loop reaches
// target. Any non-sentinel panic is re-raised.
func runMigrateWithCrash(f *DefaultStorageFactory, db *gorm.DB, target string) (err error) {
	prev := migrationCheckpoint
	migrationCheckpoint = func(label string) {
		if label == target {
			panic(migrationCrash{label})
		}
	}
	defer func() {
		migrationCheckpoint = prev
		if r := recover(); r != nil {
			if _, ok := r.(migrationCrash); ok {
				return // our simulated crash — swallow it, the on-disk state is what we test
			}
			panic(r) // a genuine panic in the code under test — let the test see it
		}
	}()
	return f.migrateDatabase(db)
}

// TestFreshInstall_InterruptedAutoMigrateLoop_NextBootMustNotSilentlyStayHalfMigrated
// is the red proof: crash right after models.Project's table is created (the
// very first model in the fresh-install loop), reopen the SAME database file
// (simulating the next boot), and run migrateDatabase again with no crash
// armed. On buggy code, the second call returns nil (success) even though
// models.User's table — the loop's SECOND entry — was never created, because
// projectsExists is now true and the early return skips the loop entirely.
func TestFreshInstall_InterruptedAutoMigrateLoop_NextBootMustNotSilentlyStayHalfMigrated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "fresh-install-crash.db")
	db1, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	crashErr := runMigrateWithCrash(f, db1, "freshinstall:after:*models.Project")
	// The simulated crash is swallowed by runMigrateWithCrash's recover; a
	// non-nil err here would mean a genuine (non-crash) failure.
	require.NoError(t, crashErr)

	// Simulate the next boot: a fresh connection to the SAME on-disk file.
	db2, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	bootErr := f.migrateDatabase(db2)
	require.NoError(t, bootErr, "next boot's migrateDatabase must not itself fail")

	if !tableExists(db2, "users") {
		t.Fatalf("BUG REPRODUCED: after an interrupted fresh install (crash right after " +
			"the projects table was created), the next boot's migrateDatabase returned " +
			"success but never created the users table — projectsExists wrongly reads " +
			"true forever and the early return permanently skips the rest of the " +
			"fresh-install loop. The server would boot \"successfully\" and fail at " +
			"runtime with \"no such table: users\" on first use.")
	}
}

// TestFreshInstall_NoCrash_AllModelsPresent is the green control: an
// uninterrupted fresh install must create every model in the loop, including
// the last one (models.MFAStepUpGrant) — the sibling-regression check for
// the fix below (a transaction that silently rolls back on success, or a
// typo narrowing the loop, would show up here).
func TestFreshInstall_NoCrash_AllModelsPresent(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "fresh-install-clean.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	for _, table := range []string{"projects", "users", "mfa_step_up_grants"} {
		assert.True(t, tableExists(db, table), "table %q must exist after an uninterrupted fresh install", table)
	}
}
