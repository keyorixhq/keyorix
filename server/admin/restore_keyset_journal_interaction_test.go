// restore_keyset_journal_interaction_test.go: the restore journal (#3583) and
// the key-set manifest (#2900) on the same half-installed restore
// (RESTORE-JOURNAL-DECIDE-1). A restore killed after it installed some of the
// archive's key files but before the manifest leaves two true statements: a
// journal exists, and the key files no longer match the manifest. The journal
// is the authority (it knows whether the data committed and how to finish);
// every check that would act on the key set must name it first, and its
// --recover must leave a set the manifest check accepts.
//
// Not t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

func TestAdminRestore_KilledMidInstall_RefusalsAndRecovery(t *testing.T) {
	for _, backend := range overwriteBackends {
		t.Run(backend, func(t *testing.T) {
			f := newOverwriteFixture(t, backend, false)
			// installed-1 is kek.salt (unchanged by the fixture's DEK rotation),
			// installed-2 is dek.key: the first point where the live key files
			// differ from what the (not yet replaced) manifest records.
			runRestoreKilledAt(t, f, "installed-2")
			cfg := f.config(t)

			require.Equal(t, f.archiveKeys["dek.key"], readOverwriteKeys(t, f.dir)["dek.key"], "sanity: the archive's dek.key is installed")
			require.Equal(t, f.liveManifest, readKeySetManifest(t, f.dir), "sanity: the manifest is installed after the key files")

			// 1. The journal check (first at boot: server/startup_checks.go).
			jerr := restorejournal.RefuseIfPresent(cfg)
			require.Error(t, jerr)
			require.Contains(t, jerr.Error(), "admin restore --recover")

			// 2. The manifest check on its own sees the half-installed set too,
			// with its own, distinct message: neither hides the other.
			merr := keyfiles.VerifyKeySetConsistency(&cfg.Storage.Encryption, ".")
			require.Error(t, merr)
			require.Contains(t, merr.Error(), "does not match the key-set manifest")
			require.Contains(t, merr.Error(), "dek.key")
			require.NotContains(t, merr.Error(), "--recover")

			// 3. A key writer names the journal, not the mismatch, and writes
			// nothing (it would land on files --recover is about to replace).
			before := readOverwriteKeys(t, f.dir)
			werr := encryptionops.RotateWithConfig(cfg, true, false, crypto.PassphraseSource{})
			require.Error(t, werr)
			require.Contains(t, werr.Error(), "admin restore --recover")
			require.NotContains(t, werr.Error(), "key-set manifest")
			require.Equal(t, before, readOverwriteKeys(t, f.dir), "a refused key writer must not touch the key files")
			require.Equal(t, f.liveManifest, readKeySetManifest(t, f.dir), "a refused key writer must not touch the manifest")

			// 4. --recover rolls forward: key files, manifest and rows are the
			// archive's, and the manifest check accepts the set.
			restoreRecover = true
			t.Cleanup(func() { restoreRecover = false })
			out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
			require.NoError(t, err, "recover output:\n%s", out)
			require.Contains(t, out, "Rolled forward")
			require.NoError(t, restorejournal.RefuseIfPresent(cfg))
			require.Equal(t, f.archiveKeys, readOverwriteKeys(t, f.dir))
			f.requireManifestRecordsArchiveKeys(t)
			require.Equal(t, []string{"in-backup"}, f.projectNames(t))
			staged, err := filepath.Glob(filepath.Join(f.dir, keyfiles.ManifestFileName+".restoring-*"))
			require.NoError(t, err)
			require.Empty(t, staged, "the staged manifest is installed, not left behind")
		})
	}
}

// A journal naming the key-set manifest as an entry is this config's own
// file; recovery accepts it like a key file. One naming a manifest in another
// directory is refused like any foreign entry.
func TestValidateJournalEntries_KeySetManifest(t *testing.T) {
	f := newOverwriteFixture(t, "sqlite", false)
	cfg := f.config(t)
	own, err := filepath.Abs(keyfiles.ManifestFileName)
	require.NoError(t, err)
	hash := restorejournal.HashBytes([]byte("m"))
	ok := restorejournal.Journal{Backend: "sqlite", Entries: []restorejournal.Entry{{Path: own, Staged: own + ".restoring-1", SHA256: hash}}}
	require.NoError(t, validateJournalEntries(cfg, ok))

	elsewhere := filepath.Join(t.TempDir(), keyfiles.ManifestFileName)
	require.NoError(t, os.WriteFile(elsewhere, []byte("x"), 0600))
	bad := restorejournal.Journal{Backend: "sqlite", Entries: []restorejournal.Entry{{Path: elsewhere, Staged: elsewhere + ".restoring-1", SHA256: hash}}}
	require.Error(t, validateJournalEntries(cfg, bad))
}
