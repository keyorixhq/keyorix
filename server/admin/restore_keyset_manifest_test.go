// restore_keyset_manifest_test.go covers how `admin restore` records the key
// set it installs in the key-set manifest (#2900) now that it installs key
// files through the restore journal (RESTORE-JOURNAL-DECIDE-1): the manifest
// is one more staged entry of the restored key set, not a separate two-phase
// write beside the journal.
//
// Not t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

func keySetTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = "sqlite"
	cfg.Storage.Database.Path = "secrets.db"
	cfg.Storage.Encryption = config.EncryptionConfig{Enabled: true, SaltPath: "kek.salt", DEKPath: "dek.key"}
	return cfg
}

// A restored key set is staged with its manifest as the last key-set entry:
// the restored hashes, one generation past the replaced manifest, nothing left
// staged. Installing the journal makes a set the boot check accepts.
func TestPrepareRestoredKeySet_StagesTheManifestWithTheKeyFiles(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false
	dir := t.TempDir()
	chdirTest(t, dir)
	cfg := keySetTestConfig()
	paths := []string{"kek.salt", "dek.key"}
	data := [][]byte{[]byte("salt-bytes-0123456789abcdef0123"), []byte("dek-bytes")}

	entries, err := prepareRestoredKeySet(cfg, paths, data)
	require.NoError(t, err)
	require.Len(t, entries, 3, "two key files and the manifest")
	wantManifest, err := filepath.Abs(keyfiles.ManifestFileName)
	require.NoError(t, err)
	require.Equal(t, wantManifest, entries[2].Path, "the manifest comes after the key files")
	for _, p := range append(paths, keyfiles.ManifestFileName) {
		_, statErr := os.Stat(p)
		require.True(t, os.IsNotExist(statErr), "staging must not touch the live %s", p)
	}

	staged, err := os.ReadFile(entries[2].Staged) // #nosec G304 -- t.TempDir() path
	require.NoError(t, err)
	var m keyfiles.Manifest
	require.NoError(t, json.Unmarshal(staged, &m))
	require.Nil(t, m.Next, "a restore stages no intent: the journal is its commit protocol")
	require.Equal(t, uint64(1), m.Generation)
	for i, name := range paths {
		require.Equal(t, keyfiles.HashBytes(data[i]), m.Files[name].SHA256, name)
		require.Equal(t, keyfiles.OpRestore, m.Files[name].Operation, name)
	}

	jpath := filepath.Join(dir, restorejournal.FileName)
	j := restorejournal.Journal{Backend: "sqlite", Timestamp: "20260101T000000Z", Entries: entries}
	require.NoError(t, restorejournal.Write(jpath, j))
	require.NoError(t, installJournalEntries(jpath, &j))
	require.NoError(t, keyfiles.VerifyKeySetConsistency(&cfg.Storage.Encryption, "."), "an installed restore must boot")
}

// A prepare failure leaves neither key files nor a staged manifest behind.
func TestPrepareRestoredKeySet_PrepareFailureStagesNothing(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false
	dir := t.TempDir()
	chdirTest(t, dir)
	cfg := keySetTestConfig()
	require.NoError(t, os.WriteFile("blocker", []byte("not-a-directory"), 0600))

	_, err := prepareRestoredKeySet(cfg, []string{"kek.salt", filepath.Join("blocker", "dek.key")},
		[][]byte{[]byte("salt-bytes"), []byte("dek-bytes")})
	require.Error(t, err)
	names, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range names {
		require.Contains(t, []string{"blocker"}, e.Name(), "nothing may be staged or installed after a failed prepare")
	}
}

// Without --overwrite-existing an existing manifest is refused before anything
// is staged: it would otherwise make the journal's install (a no-clobber link)
// fail after the data has committed.
func TestRefuseExistingKeySetManifest(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	dir := t.TempDir()
	chdirTest(t, dir)
	cfg := keySetTestConfig()

	restoreOverwriteExisting = false
	require.NoError(t, refuseExistingKeySetManifest(cfg), "no manifest: nothing to refuse")
	require.NoError(t, os.WriteFile(keyfiles.ManifestFileName, []byte(`{"format":1}`), 0600))
	err := refuseExistingKeySetManifest(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key-set manifest")
	require.Contains(t, err.Error(), "--overwrite-existing")

	restoreOverwriteExisting = true
	require.NoError(t, refuseExistingKeySetManifest(cfg), "--overwrite-existing moves it aside like the key files")
}
