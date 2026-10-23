package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// A restore records the set it installed in the key-set manifest (#2900):
// the restored hashes, one new generation, nothing left staged.
func TestWriteRestoredFileSet_RecordsTheRestoredSetInTheManifest(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	enc := &config.EncryptionConfig{SaltPath: "kek.salt", DEKPath: "dek.key"}
	ks, err := keyfiles.NewSetWriter(enc, dir)
	require.NoError(t, err)
	paths := []string{filepath.Join(dir, "kek.salt"), filepath.Join(dir, "dek.key")}
	data := [][]byte{[]byte("salt-bytes"), []byte("dek-bytes")}

	require.NoError(t, writeRestoredFileSet(paths, data, "20260101T000000Z", ks))

	m, err := keyfiles.LoadManifest(filepath.Join(dir, keyfiles.ManifestFileName))
	require.NoError(t, err)
	require.Nil(t, m.Next, "nothing may stay staged after a completed restore")
	require.Equal(t, uint64(1), m.Generation)
	for i, name := range []string{"kek.salt", "dek.key"} {
		require.Equal(t, keyfiles.HashBytes(data[i]), m.Files[name].SHA256, name)
		require.Equal(t, keyfiles.OpRestore, m.Files[name].Operation, name)
	}
	require.NoError(t, keyfiles.VerifyKeySetConsistency(enc, dir), "a completed restore must boot")
}

// The stage happens after every file is prepared and before any is installed:
// a prepare failure leaves neither key files nor a staged manifest behind.
func TestWriteRestoredFileSet_PrepareFailureStagesNothing(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	ks := keyfiles.NewSetWriterForFiles(dir, filepath.Join(dir, "kek.salt"), filepath.Join(dir, "dek.key"))
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not-a-directory"), 0600))

	err := writeRestoredFileSet(
		[]string{filepath.Join(dir, "kek.salt"), filepath.Join(blocker, "dek.key")},
		[][]byte{[]byte("salt-bytes"), []byte("dek-bytes")},
		"20260101T000000Z", ks,
	)
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(dir, keyfiles.ManifestFileName))
	require.True(t, os.IsNotExist(statErr), "no manifest may be written when nothing was installed: %v", statErr)
}
