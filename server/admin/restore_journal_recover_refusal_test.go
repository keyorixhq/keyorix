// restore_journal_recover_refusal_test.go covers RESTORE-OVERWRITE-FIX-2:
// `admin restore --recover` must not roll a restore forward on the word of a
// journal whose staged files it cannot vouch for. Power loss can drop a
// staged key file's directory entry (its directory was never fsynced) while
// the journal and the committed data survive; recovery used to read the
// missing staged file as "already installed", remove the journal and leave
// the OLD keys beside the NEW data. Each test kills a real restore process
// (runRestoreKilledAt), damages what it left the way a crash or a planted
// file would, and requires --recover to refuse and change nothing.
package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

// commitStepFor is the first step after which a killed restore must be
// rolled forward: the SQLite journal is the commit point, the PostgreSQL
// load transaction's COMMIT is.
func commitStepFor(backend string) string {
	if backend == "postgres" {
		return "committed"
	}
	return "journal-written"
}

func stagedKeyFile(t *testing.T, f *overwriteFixture, name string) string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(f.dir, name+".restoring-*"))
	require.NoError(t, err)
	require.Len(t, m, 1, "exactly one staged copy of %s", name)
	return m[0]
}

func runRecover(t *testing.T) (string, error) {
	t.Helper()
	restoreRecover = true
	t.Cleanup(func() { restoreRecover = false })
	return captureStdout(t, func() error { return runAdminRestore(nil, nil) })
}

// requireRecoveryRefusedUntouched: the journal is still there (the server
// keeps refusing to start), the live key files are what they were before
// the restore, and the staged files recovery could not vouch for were left
// for the operator.
func requireRecoveryRefusedUntouched(t *testing.T, f *overwriteFixture, err error, out string) {
	t.Helper()
	require.Error(t, err, "recover output:\n%s", out)
	require.Contains(t, err.Error(), "recovery refuses")
	require.Error(t, restorejournal.RefuseIfPresent(f.config(t)), "the journal must be kept: the server must keep refusing to start")
	require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir), "a refused recovery must not install any key file")
	aside, gerr := filepath.Glob(filepath.Join(f.dir, "*.pre-restore-*"))
	require.NoError(t, gerr)
	require.Empty(t, aside, "a refused recovery must not move any live file aside")
}

// TestAdminRestoreRecover_RefusesLostStagedKeyFile: the staged dek.key is
// gone after the commit point (its directory entry lost to power loss) and
// the live dek.key is the pre-restore one. Rolling forward would pair the
// archive's data with the old DEK.
func TestAdminRestoreRecover_RefusesLostStagedKeyFile(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)
			runRestoreKilledAt(t, f, commitStepFor(backend))
			require.NoError(t, os.Remove(stagedKeyFile(t, f, "dek.key")))

			out, err := runRecover(t)
			requireRecoveryRefusedUntouched(t, f, err, out)
			require.Contains(t, err.Error(), "dek.key")
		})
	}
}

// TestAdminRestoreRecover_RefusesDamagedStagedKeyFile: a staged file whose
// content is not what the restore staged (torn by a crash, or replaced by
// someone with write access to the key directory) is never installed.
func TestAdminRestoreRecover_RefusesDamagedStagedKeyFile(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)
			runRestoreKilledAt(t, f, commitStepFor(backend))
			require.NoError(t, os.WriteFile(stagedKeyFile(t, f, "dek.key"), []byte("not the archived DEK"), 0600))

			out, err := runRecover(t)
			requireRecoveryRefusedUntouched(t, f, err, out)
		})
	}
}

// TestAdminRestoreRecover_RefusesForeignWitnessPath: the journal's witness
// path is where --recover writes the rollback-protection high-water mark. A
// journal pointing it anywhere but this deployment's own witness location
// is refused before anything is renamed or written.
func TestAdminRestoreRecover_RefusesForeignWitnessPath(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)
			runRestoreKilledAt(t, f, commitStepFor(backend))
			jpath := filepath.Join(f.dir, restorejournal.FileName)
			j, found, err := restorejournal.Read(jpath)
			require.NoError(t, err)
			require.True(t, found)
			foreign := filepath.Join(t.TempDir(), "planted-witness")
			j.WitnessPath = foreign
			if j.WitnessValue == "" {
				j.WitnessValue = "1"
			}
			require.NoError(t, restorejournal.Write(jpath, j))

			out, err := runRecover(t)
			requireRecoveryRefusedUntouched(t, f, err, out)
			require.Contains(t, err.Error(), "witness")
			_, statErr := os.Stat(foreign)
			require.True(t, os.IsNotExist(statErr), "nothing may be written to the planted witness path")
		})
	}
}

// TestAdminRestoreRecover_RemovesOrphanStagedFiles: a restore killed after
// staging but before its journal leaves *.restoring-* copies of the
// archive's key material (0600) next to the live files and no journal.
// --recover removes them and says so; the live files are untouched.
func TestAdminRestoreRecover_RemovesOrphanStagedFiles(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)
			step := "journal-written" // PostgreSQL: before the load; the journal is removed on the way out
			if backend == "sqlite" {
				step = "loaded" // the staged database is complete, the journal not yet written
			}
			// A kill leaves no Go cleanup; on PostgreSQL the journal is written
			// before the load, so drop it to model the crash before Write.
			runRestoreKilledAt(t, f, step)
			_ = os.Remove(filepath.Join(f.dir, restorejournal.FileName))
			orphans, err := filepath.Glob(filepath.Join(f.dir, "*.restoring-*"))
			require.NoError(t, err)
			require.NotEmpty(t, orphans, "sanity: the killed restore must have left staged files")

			out, err := runRecover(t)
			require.NoError(t, err, "recover output:\n%s", out)
			require.Contains(t, out, "leftover")
			require.Empty(t, f.restoreLeftovers(t), "every orphan staged file must be removed")
			require.Equal(t, f.liveKeys, readOverwriteKeys(t, f.dir))
			require.Equal(t, []string{"after-backup", "in-backup"}, f.projectNames(t))
		})
	}
}
