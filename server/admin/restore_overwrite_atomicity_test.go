// restore_overwrite_atomicity_test.go covers RESTORE-OVERWRITE-FIX-1:
// `admin restore --overwrite-existing` into a populated deployment must be
// all-or-nothing. On PostgreSQL the archive's key files used to be installed
// BEFORE the data load, so a load that then failed left the live install with
// the archive's keys and its own (old) rows -- secrets encrypted under the
// replaced DEK no longer decrypted (UPGRADE-ROLLBACK-1, bug 1). On SQLite the
// keys were installed and the live database moved aside before the load, so a
// failed load left the archive's keys beside an empty database.
//
// Every test runs on both backends; the PostgreSQL leg is gated on
// KEYORIX_TEST_PG_DSN (pgAdminTestDSN). Not t.Parallel(): package-level cobra
// flag vars and chdir, this package's convention.
package admin

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const overwriteTestPassphrase = "test-passphrase-1234"

var overwriteBackends = []string{"sqlite", "postgres"}

// overwriteFixture is a live deployment that was backed up, then moved on:
// its DEK was rotated and a project was added after the backup.
type overwriteFixture struct {
	backend     string
	dir         string
	cfgPath     string
	archive     string
	archiveKeys map[string][]byte // key files as the archive holds them
	liveKeys    map[string][]byte // key files on disk right before the restore
}

var overwriteKeyNames = []string{"dek.key", "kek.salt"}

func readOverwriteKeys(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range overwriteKeyNames {
		b, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- t.TempDir() path
		require.NoError(t, err)
		out[name] = b
	}
	return out
}

// newOverwriteFixture builds the fixture. With danglingRef the backed-up data
// holds an environment whose project does not exist: backup only warns about
// it, restore's mandatory post-load check refuses it -- a load that fails
// AFTER the archive passed every pre-write check (signature, rollback), the
// failure class this file is about.
func newOverwriteFixture(t *testing.T, backend string, danglingRef bool) *overwriteFixture {
	t.Helper()
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", overwriteTestPassphrase)

	f := &overwriteFixture{backend: backend, dir: t.TempDir()}
	chdirTest(t, f.dir)
	switch backend {
	case "sqlite":
		f.cfgPath = writeBackupRestoreTestConfig(t, f.dir, filepath.Join(f.dir, "secrets.db"))
	case "postgres":
		f.cfgPath = writePostgresBackupRestoreTestConfig(t, f.dir, pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t)))
	default:
		t.Fatalf("unknown backend %q", backend)
	}
	configPathFlag = f.cfgPath

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, f.dir).Initialize(overwriteTestPassphrase))
	cfg := f.config(t)
	_, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	f.withDB(t, func(db *gorm.DB) {
		require.NoError(t, db.Create(&models.Project{Name: "in-backup"}).Error)
		if danglingRef {
			require.NoError(t, db.Create(&models.Environment{ProjectID: 999, Name: "orphan"}).Error)
		}
	})

	f.archive = filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = f.archive
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "backup output:\n%s", out)
	f.archiveKeys = readOverwriteKeys(t, f.dir)

	// The deployment moves on: DEK rotation (new dek.key) and new data.
	require.NoError(t, encryptionops.RotateWithConfig(cfg, true, false, crypto.PassphraseSource{}))
	f.withDB(t, func(db *gorm.DB) {
		require.NoError(t, db.Create(&models.Project{Name: "after-backup"}).Error)
	})
	f.liveKeys = readOverwriteKeys(t, f.dir)
	require.NotEqual(t, f.archiveKeys["dek.key"], f.liveKeys["dek.key"], "sanity: rotation must change dek.key")

	restoreInput = f.archive
	restoreOverwriteExisting = true
	restoreAllowRollback = true
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	return f
}

func (f *overwriteFixture) config(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(f.cfgPath)
	require.NoError(t, err)
	return cfg
}

// withDB opens the deployment's database, runs fn, and closes it again, so no
// handle is open across a restore.
func (f *overwriteFixture) withDB(t *testing.T, fn func(db *gorm.DB)) {
	t.Helper()
	db, err := storage.OpenGormDB(f.config(t))
	require.NoError(t, err)
	defer closeGormDB(db)
	fn(db)
}

func (f *overwriteFixture) projectNames(t *testing.T) []string {
	t.Helper()
	var names []string
	f.withDB(t, func(db *gorm.DB) {
		require.NoError(t, db.Model(&models.Project{}).Order("name").Pluck("name", &names).Error)
	})
	sort.Strings(names)
	return names
}

func (f *overwriteFixture) auditEventCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	f.withDB(t, func(db *gorm.DB) {
		require.NoError(t, db.Model(&models.AuditEvent{}).Count(&n).Error)
	})
	return n
}

// restoreLeftovers lists every file a restore writes beside the live ones:
// moved-aside originals, staged temp copies, the restore journal.
func (f *overwriteFixture) restoreLeftovers(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pattern := range []string{"*.pre-restore-*", "*.restoring-*", restorejournal.FileName} {
		m, err := filepath.Glob(filepath.Join(f.dir, pattern))
		require.NoError(t, err)
		for _, p := range m {
			out = append(out, filepath.Base(p))
		}
	}
	return out
}

// requirePreRestoreStateIntact is the failure-path contract: the key files
// are byte-identical to what was live before the restore, the rows are the
// live rows (not the archive's), the audit trail did not move, and nothing
// was left beside the live files.
func (f *overwriteFixture) requirePreRestoreStateIntact(t *testing.T, auditBefore int64) {
	t.Helper()
	require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir), "a failed restore must leave the live key files byte-identical")
	require.Equal(t, []string{"after-backup", "in-backup"}, f.projectNames(t), "a failed restore must leave the live rows")
	require.Equal(t, auditBefore, f.auditEventCount(t), "a failed restore must not change the audit trail")
	require.Empty(t, f.restoreLeftovers(t), "a failed restore must leave nothing beside the live files")
}

// TestAdminRestore_Overwrite_FailingLoad_LeavesPreRestoreStateIntact is the
// red test for the bug: a signed archive whose load fails (here the mandatory
// dangling-reference check) restored with --overwrite-existing over a live,
// rotated deployment. Before the fix both backends left the archive's
// dek.key installed (the live one moved aside), SQLite also an empty DB.
func TestAdminRestore_Overwrite_FailingLoad_LeavesPreRestoreStateIntact(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, true)
			auditBefore := f.auditEventCount(t)

			out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
			require.Error(t, err, "output:\n%s", out)
			f.requirePreRestoreStateIntact(t, auditBefore)
			require.Contains(t, err.Error(), "dangling reference")
		})
	}
}

// TestAdminRestore_Overwrite_PopulatedTarget_ReplacesKeysAndData: the success
// path over a populated deployment replaces BOTH halves -- keys are the
// archive's, rows are the archive's -- keeps the replaced key files aside,
// and the restored audit chain verifies. On PostgreSQL this used to fail on
// the first colliding primary key (permissions_pkey in the field), after the
// keys had already been swapped.
func TestAdminRestore_Overwrite_PopulatedTarget_ReplacesKeysAndData(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)

			out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
			require.NoError(t, err, "output:\n%s", out)
			require.Contains(t, out, "verify-audit on the restored database: VALID")

			require.Equal(t, f.archiveKeys, readOverwriteKeys(t, f.dir), "key files must be the archive's")
			require.Equal(t, []string{"in-backup"}, f.projectNames(t), "rows must be the archive's")

			aside, err := filepath.Glob(filepath.Join(f.dir, "dek.key.pre-restore-*"))
			require.NoError(t, err)
			require.Len(t, aside, 1, "the replaced dek.key must be kept aside")
			got, err := os.ReadFile(aside[0]) // #nosec G304 -- t.TempDir() path
			require.NoError(t, err)
			require.Equal(t, f.liveKeys["dek.key"], got)

			journal, err := filepath.Glob(filepath.Join(f.dir, restorejournal.FileName))
			require.NoError(t, err)
			require.Empty(t, journal, "a completed restore must remove its journal")
		})
	}
}

// TestAdminRestore_Overwrite_FailureInsideCommitTransaction: a failure at the
// last step inside the PostgreSQL load transaction (every row loaded,
// sequences resynced, token written) and, on SQLite, right after the staged
// database is complete. Nothing may be left changed -- in particular the
// sequences: setval is not transactional, so a resync that lowered one would
// make the next insert collide with a live row after the rollback.
func TestAdminRestore_Overwrite_FailureInsideCommitTransaction(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)
			auditBefore := f.auditEventCount(t)
			orig := restoreStepHook
			t.Cleanup(func() { restoreStepHook = orig })
			restoreStepHook = func(step string) error {
				if step == "loaded" {
					return errors.New("injected failure at step loaded")
				}
				return nil
			}

			out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
			require.Error(t, err, "output:\n%s", out)
			require.Contains(t, err.Error(), "injected failure")
			f.requirePreRestoreStateIntact(t, auditBefore)

			f.withDB(t, func(db *gorm.DB) {
				require.NoError(t, db.Create(&models.Project{Name: "after-failed-restore"}).Error,
					"the next insert after a rolled-back restore must not collide with a live row")
			})
		})
	}
}

// TestAdminRestore_Postgres_OverwriteMatchesFreshRestore: an in-place
// --overwrite-existing restore leaves every table (registry or not) with the
// same row count as restoring the same archive into a fresh database, so
// clearPostgresRestoreTarget clears exactly what a fresh migration would not
// have.
func TestAdminRestore_Postgres_OverwriteMatchesFreshRestore(t *testing.T) {
	f := newOverwriteFixture(t, "postgres", false)
	_, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err)
	inPlace := pgTableRowCounts(t, f.config(t).Storage.Database.DSN)

	freshDir := t.TempDir()
	chdirTest(t, freshDir)
	freshDSN := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	configPathFlag = writePostgresBackupRestoreTestConfig(t, freshDir, freshDSN)
	restoreOverwriteExisting = false
	restoreAllowRollback = false
	_, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err)
	fresh := pgTableRowCounts(t, freshDSN)

	require.Equal(t, fresh, inPlace)
}

func pgTableRowCounts(t *testing.T, dsn string) map[string]int64 {
	t.Helper()
	db := pgAdminRawOpen(t, dsn)
	var tables []string
	require.NoError(t, db.Raw(`SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`).Scan(&tables).Error)
	out := map[string]int64{}
	for _, name := range tables {
		var n int64
		require.NoError(t, db.Table(name).Count(&n).Error)
		out[name] = n
	}
	return out
}

// restoreKillEnv carries a kill-point run into the helper process.
const restoreKillEnv = "KEYORIX_TEST_RESTORE_KILL_AT"

// restoreKillExitCode is what the helper exits with at the kill point.
const restoreKillExitCode = 77

// TestAdminRestoreKillPointHelper is not a test: run as a subprocess by
// runRestoreKilledAt, it restores with the parent's flags and exits the
// process -- no deferred cleanup, no rollback from Go -- at the named step.
func TestAdminRestoreKillPointHelper(t *testing.T) {
	step := os.Getenv(restoreKillEnv)
	if step == "" {
		t.Skip("helper process for the kill-point tests")
	}
	require.NoError(t, i18n.InitializeForTesting())
	configPathFlag = os.Getenv("KEYORIX_TEST_RESTORE_CFG")
	restoreInput = os.Getenv("KEYORIX_TEST_RESTORE_INPUT")
	restoreOverwriteExisting, restoreAllowRollback = true, true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	restoreStepHook = func(s string) error {
		if s == step {
			os.Exit(restoreKillExitCode)
		}
		return nil
	}
	err := runAdminRestore(nil, nil)
	t.Fatalf("restore was not killed at step %q (err: %v)", step, err)
}

func runRestoreKilledAt(t *testing.T, f *overwriteFixture, step string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAdminRestoreKillPointHelper$", "-test.count=1") // #nosec G204 -- the test binary itself
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), restoreKillEnv+"="+step,
		"KEYORIX_TEST_RESTORE_CFG="+f.cfgPath, "KEYORIX_TEST_RESTORE_INPUT="+f.archive)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "helper output:\n%s", out)
	require.Equal(t, restoreKillExitCode, exitErr.ExitCode(), "helper output:\n%s", out)
}

// TestAdminRestore_Overwrite_KillPoints kills a real restore process at each
// step boundary of the commit sequence (restore_commit.go), then checks what
// it left and that `admin restore --recover` resolves it: rolled back to the
// live keys and rows before the commit point, rolled forward to the archive's
// keys and rows after it. While a journal exists the server's boot check and
// a plain restore both refuse.
func TestAdminRestore_Overwrite_KillPoints(t *testing.T) {
	cases := []struct {
		backend, step string
		journal       bool // a journal is left behind
		forward       bool // recovery rolls forward
	}{
		{"sqlite", "staged", false, false},
		{"sqlite", "loaded", false, false},
		{"sqlite", "journal-written", true, true},
		{"sqlite", "moved-aside", true, true},
		{"sqlite", "installed-1", true, true},
		{"sqlite", "installed-3", true, true}, // the last entry: the database
		{"sqlite", "finishing", true, true},
		{"postgres", "staged", false, false},
		{"postgres", "journal-written", true, false},
		{"postgres", "loaded", true, false},
		{"postgres", "committed", true, true},
		{"postgres", "moved-aside", true, true},
		{"postgres", "installed-1", true, true},
		{"postgres", "installed-2", true, true}, // the last key file
		{"postgres", "finishing", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.backend+"/"+tc.step, func(t *testing.T) {
			f := newOverwriteFixture(t, tc.backend, false)
			auditBefore := f.auditEventCount(t)
			runRestoreKilledAt(t, f, tc.step)

			cfg := f.config(t)
			bootErr := restorejournal.RefuseIfPresent(cfg)
			if !tc.journal {
				require.NoError(t, bootErr)
				require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir))
				require.Equal(t, []string{"after-backup", "in-backup"}, f.projectNames(t))
				require.Equal(t, auditBefore, f.auditEventCount(t))
				// The staged copies the killed process left are removed by
				// the next --recover (or restore).
				restoreRecover = true
				t.Cleanup(func() { restoreRecover = false })
				out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
				require.NoError(t, err, "recover output:\n%s", out)
				require.Empty(t, f.restoreLeftovers(t))
				require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir))
				return
			}
			require.Error(t, bootErr, "the boot check must refuse while a restore journal exists")
			require.Contains(t, bootErr.Error(), "admin restore --recover")
			err := runAdminRestore(nil, nil)
			require.Error(t, err, "a new restore must refuse while a journal exists")
			require.Contains(t, err.Error(), "admin restore --recover")
			backupOutput = filepath.Join(t.TempDir(), "during-journal.tar.gz")
			err = runAdminBackup(nil, nil)
			require.Error(t, err, "a backup must refuse while a journal exists")
			require.Contains(t, err.Error(), "admin restore --recover")

			if tc.step == "finishing" {
				j, _, jerr := restorejournal.Read(filepath.Join(f.dir, restorejournal.FileName))
				require.NoError(t, jerr)
				require.True(t, j.Installed, "the journal must record the install before the finish step starts")
			}

			restoreRecover = true
			t.Cleanup(func() { restoreRecover = false })
			out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
			require.NoError(t, err, "recover output:\n%s", out)
			require.NoError(t, restorejournal.RefuseIfPresent(cfg), "recovery must remove the journal")
			if tc.step == "finishing" {
				// Documented (restore-failure-modes.md): the finish step's audit
				// events precede the journal's removal, so a crash between them
				// records them twice -- never zero times.
				var completed int64
				f.withDB(t, func(db *gorm.DB) {
					require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "admin.restore_completed").Count(&completed).Error)
				})
				require.Equal(t, int64(2), completed)
			}

			if tc.forward {
				require.Contains(t, out, "Rolled forward")
				require.Contains(t, out, "verify-audit on the restored database: VALID")
				require.Equal(t, f.archiveKeys, readOverwriteKeys(t, f.dir))
				require.Equal(t, []string{"in-backup"}, f.projectNames(t))
				leftovers, gerr := filepath.Glob(filepath.Join(f.dir, "*.restoring-*"))
				require.NoError(t, gerr)
				require.Empty(t, leftovers)
				return
			}
			require.Contains(t, out, "Rolled back")
			require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir))
			require.Equal(t, []string{"after-backup", "in-backup"}, f.projectNames(t))
			require.Equal(t, auditBefore+1, f.auditEventCount(t), "only the recovery's own audit event is new")
			require.Empty(t, f.restoreLeftovers(t))
		})
	}
}

// TestAdminRestoreRecover_RefusesForeignJournalEntries: --recover renames the
// files a journal names, and a journal is a file anyone with write access to
// the data directory could plant. It must refuse an entry outside this
// config's own key files and database, or a staged name that is not a
// restore staging file next to its target, and rename nothing.
func TestAdminRestoreRecover_RefusesForeignJournalEntries(t *testing.T) {
	planted := restorejournal.HashBytes([]byte("planted"))
	cases := map[string]func(dir string) restorejournal.Entry{
		"foreign target": func(dir string) restorejournal.Entry {
			return restorejournal.Entry{Path: filepath.Join(dir, "elsewhere.txt"), Staged: filepath.Join(dir, "elsewhere.txt.restoring-1"), SHA256: planted}
		},
		"foreign staged": func(dir string) restorejournal.Entry {
			return restorejournal.Entry{Path: filepath.Join(dir, "dek.key"), Staged: filepath.Join(dir, "planted-dek"), SHA256: planted}
		},
		"other directory": func(dir string) restorejournal.Entry {
			sub := filepath.Join(dir, "sub")
			_ = os.MkdirAll(sub, 0o750)
			return restorejournal.Entry{Path: filepath.Join(dir, "dek.key"), Staged: filepath.Join(sub, "dek.key.restoring-1"), SHA256: planted}
		},
		"relative target": func(string) restorejournal.Entry {
			return restorejournal.Entry{Path: "dek.key", Staged: "dek.key.restoring-1", SHA256: planted}
		},
		"no content hash": func(dir string) restorejournal.Entry {
			return restorejournal.Entry{Path: filepath.Join(dir, "dek.key"), Staged: filepath.Join(dir, "dek.key.restoring-1")}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOverwriteFixture(t, "sqlite", false)
			entry := mk(f.dir)
			staged := entry.Staged
			if !filepath.IsAbs(staged) {
				staged = filepath.Join(f.dir, staged)
			}
			require.NoError(t, os.WriteFile(staged, []byte("planted"), 0600))
			jpath := filepath.Join(f.dir, restorejournal.FileName)
			require.NoError(t, restorejournal.Write(jpath, restorejournal.Journal{
				Backend: "sqlite", Timestamp: "20260101T000000Z", Overwrite: true, Entries: []restorejournal.Entry{entry}}))

			restoreRecover = true
			t.Cleanup(func() { restoreRecover = false })
			_, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
			require.Error(t, err)
			require.Contains(t, err.Error(), "recovery refuses to act on it")
			require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir), "nothing may be renamed")
			_, statErr := os.Stat(jpath)
			require.NoError(t, statErr, "the journal must be left for the operator to inspect")
		})
	}
}
