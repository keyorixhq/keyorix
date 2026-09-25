// backup_restore_test.go covers the hardening the #2099 review asked for on
// admin backup/admin restore (server/admin/backup.go, restore.go): bounded
// decompression (readBackupArchive never buffers more than its caps allow,
// regardless of what an archive claims), 0600-always + fsync on every
// restored file, atomic temp-file-then-rename/link writes that leave an
// existing target unchanged on failure, and rejection of non-regular/
// duplicate/unlisted tar entries. FuzzReadBackupArchive at the bottom is the
// same property continuously: never panics, never reads past its caps.
//
// Not t.Parallel(): several tests here mutate the package-level cobra flag
// var restoreOverwriteExisting, matching this package's existing convention
// (see fuzz_encryption_command_fault_test.go's captureStdout doc comment).
package admin

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// resetRestoreOverwriteFlag restores restoreOverwriteExisting after a test
// that sets it, so state never leaks across tests (mirrors
// resetVerifyAuditAndExportFlags in audit_offline_anchor_test.go).
func resetRestoreOverwriteFlag(t *testing.T) {
	t.Helper()
	orig := restoreOverwriteExisting
	t.Cleanup(func() { restoreOverwriteExisting = orig })
}

// buildTestManifest builds a backupManifest whose DBFile/KeyFiles entries
// correctly describe dbData/keyData (correct SHA256 + Size), the shape
// writeBackupArchive itself produces.
func buildTestManifest(dbData []byte, keyData [][]byte) backupManifest {
	dbSum := sha256.Sum256(dbData)
	m := backupManifest{
		FormatVersion: backupFormatVersion,
		CreatedAt:     time.Now().UTC(),
		Backend:       "sqlite",
		DBFile: backupFileEntry{
			OriginalPath: "db.sqlite",
			TarName:      "db.sqlite",
			Mode:         0600,
			SHA256:       hex.EncodeToString(dbSum[:]),
			Size:         int64(len(dbData)),
		},
	}
	for i, kb := range keyData {
		sum := sha256.Sum256(kb)
		m.KeyFiles = append(m.KeyFiles, backupFileEntry{
			OriginalPath: filepath.Join("keys", string(rune('a'+i))),
			TarName:      "keyfiles/" + string(rune('0'+i)),
			Mode:         0600,
			SHA256:       hex.EncodeToString(sum[:]),
			Size:         int64(len(kb)),
		})
	}
	return m
}

func TestReadBackupArchive_ValidRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbData := []byte("fake-db-bytes")
	keyData := [][]byte{[]byte("key-material-1"), []byte("key-material-2")}
	manifest := buildTestManifest(dbData, keyData)

	path := filepath.Join(dir, "backup.tar.gz")
	require.NoError(t, writeBackupArchive(path, manifest, dbData, keyData))

	gotManifest, gotDB, gotKeys, err := readBackupArchive(path, 0, 0)
	require.NoError(t, err)
	require.Equal(t, manifest.Backend, gotManifest.Backend)
	require.Equal(t, manifest.FormatVersion, gotManifest.FormatVersion)
	require.Equal(t, dbData, gotDB)
	require.Len(t, gotKeys, len(keyData))
	for i := range keyData {
		require.Equal(t, keyData[i], gotKeys[i])
	}
}

func TestReadBackupArchive_RejectsDeclaredSizeAboveMaxEntryBytes(t *testing.T) {
	dir := t.TempDir()
	dbData := []byte("small")
	manifest := buildTestManifest(dbData, nil)
	// The manifest LIES about its own database entry's size -- a hostile
	// archive declaring a huge size to try to force a huge allocation, even
	// though the real tar entry (written below) is tiny.
	manifest.DBFile.Size = 10_000_000_000

	path := filepath.Join(dir, "backup.tar.gz")
	require.NoError(t, writeBackupArchive(path, manifest, dbData, nil))

	_, _, _, err := readBackupArchive(path, 4096, 1<<20)
	require.Error(t, err)
	require.Contains(t, err.Error(), "per-entry limit")
}

func TestReadBackupArchive_RejectsEntryExceedingItsOwnDeclaredSize(t *testing.T) {
	// The manifest declares an honest, small size for db.sqlite, but the
	// actual tar entry bytes are much larger -- the decompression-bomb
	// shape: readCapped must stop at the declared size (bounded read), never
	// buffer the full oversized entry to find out it's wrong.
	dbData := []byte("small-declared-size")
	manifest := buildTestManifest(dbData, nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.tar.gz")
	oversized := make([]byte, len(dbData)+50_000)
	writeRawTestArchive(t, path, []rawEntry{
		{name: "MANIFEST.json", data: mustMarshalManifest(t, manifest)},
		{name: "db.sqlite", data: oversized},
	})

	_, _, _, err := readBackupArchive(path, 1<<20, 1<<20)
	require.Error(t, err)
	require.Contains(t, err.Error(), "per-entry size limit")
}

func TestReadBackupArchive_TotalBytesCapped(t *testing.T) {
	dbData := make([]byte, 600)
	keyData := [][]byte{make([]byte, 600)}
	manifest := buildTestManifest(dbData, keyData)

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.tar.gz")
	require.NoError(t, writeBackupArchive(path, manifest, dbData, keyData))

	// Each entry individually fits under maxEntryBytes, but the two
	// together exceed maxTotalBytes.
	_, _, _, err := readBackupArchive(path, 2000, 1000)
	require.Error(t, err)
	require.Contains(t, err.Error(), "total decompressed size limit")
}

func TestReadBackupArchive_RejectsSymlinkEntry(t *testing.T) {
	manifest := buildTestManifest([]byte("db"), nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.tar.gz")
	writeRawTestArchive(t, path, []rawEntry{
		{name: "MANIFEST.json", data: mustMarshalManifest(t, manifest)},
		{name: "db.sqlite", typeflag: tar.TypeSymlink, data: []byte("/etc/passwd")},
	})

	_, _, _, err := readBackupArchive(path, 0, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a regular file")
}

func TestReadBackupArchive_RejectsDuplicateEntry(t *testing.T) {
	keyData := [][]byte{[]byte("key")}
	manifest := buildTestManifest([]byte("db"), keyData)
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.tar.gz")
	writeRawTestArchive(t, path, []rawEntry{
		{name: "MANIFEST.json", data: mustMarshalManifest(t, manifest)},
		{name: "db.sqlite", data: []byte("db")},
		{name: "keyfiles/0", data: keyData[0]},
		{name: "keyfiles/0", data: keyData[0]}, // duplicate
	})

	_, _, _, err := readBackupArchive(path, 0, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate entry")
}

func TestReadBackupArchive_RejectsUnlistedEntry(t *testing.T) {
	manifest := buildTestManifest([]byte("db"), nil) // no key files referenced
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.tar.gz")
	writeRawTestArchive(t, path, []rawEntry{
		{name: "MANIFEST.json", data: mustMarshalManifest(t, manifest)},
		{name: "db.sqlite", data: []byte("db")},
		{name: "keyfiles/0", data: []byte("not referenced by the manifest")},
	})

	_, _, _, err := readBackupArchive(path, 0, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not referenced by its own MANIFEST.json")
}

func TestReadBackupArchive_RequiresManifestFirst(t *testing.T) {
	manifest := buildTestManifest([]byte("db"), nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.tar.gz")
	writeRawTestArchive(t, path, []rawEntry{
		{name: "db.sqlite", data: []byte("db")},
		{name: "MANIFEST.json", data: mustMarshalManifest(t, manifest)},
	})

	_, _, _, err := readBackupArchive(path, 0, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected MANIFEST.json")
}

// TestWriteRestoredFile_AlwaysWrites0600 is the "mode clamped" case (#2099
// review item 2): writeRestoredFile no longer takes a mode argument at all
// -- every restored file is restoreFileMode regardless of what the archive's
// manifest recorded for it.
func TestWriteRestoredFile_AlwaysWrites0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restored.key")
	require.NoError(t, writeRestoredFile(path, []byte("secret"), "20260101T000000Z"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(restoreFileMode), info.Mode().Perm())

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

func TestWriteRestoredFile_OverwriteExisting_MovesAsideNotTruncates(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = true

	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(path, []byte("old-data"), 0600))

	ts := "20260102T030405Z"
	require.NoError(t, writeRestoredFile(path, []byte("new-data"), ts))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new-data", string(got))

	aside := path + ".pre-restore-" + ts
	gotAside, err := os.ReadFile(aside)
	require.NoError(t, err, "the pre-existing file must be moved aside, not discarded")
	require.Equal(t, "old-data", string(gotAside))
}

func TestWriteRestoredFile_NoOverwrite_RefusesConcurrentNonEmptyFile(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(path, []byte("someone-else-wrote-this"), 0600))

	err := writeRestoredFile(path, []byte("new-data"), "20260101T000000Z")
	require.Error(t, err)

	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "someone-else-wrote-this", string(got), "a refused write must not touch the existing file")
}

func TestWriteRestoredFile_NoOverwrite_ReplacesEmptyPlaceholder(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(path, nil, 0600)) // 0-byte placeholder

	require.NoError(t, writeRestoredFile(path, []byte("new-data"), "20260101T000000Z"))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new-data", string(got))
}

// TestWriteRestoredFile_FailureLeavesTargetUnchanged is the #2099 review's
// own example (item 3/6): "a crash midway (e.g. key file ok, DB write
// fails) leaves the target unchanged." The DB file's directory is made
// unwritable AFTER an existing (empty) placeholder is created there, so the
// temp-file-then-link write for dbPath fails, while a sibling key file
// write (different, writable directory) succeeds -- proving the atomic
// write leaves dbPath's prior content exactly as it was.
func TestWriteRestoredFile_FailureLeavesTargetUnchanged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory write permissions")
	}
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "keys", "dek.key")

	dbDir := filepath.Join(dir, "dbdir")
	dbPath := filepath.Join(dbDir, "secrets.db")
	require.NoError(t, os.MkdirAll(dbDir, 0750))
	require.NoError(t, os.WriteFile(dbPath, nil, 0600)) // pre-existing empty placeholder
	require.NoError(t, os.Chmod(dbDir, 0500))            // read+execute only: no new files can be created
	t.Cleanup(func() { _ = os.Chmod(dbDir, 0750) })      // let t.TempDir() clean up afterward

	ts := "20260101T000000Z"

	require.NoError(t, writeRestoredFile(keyPath, []byte("key-bytes"), ts))
	got, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, "key-bytes", string(got))

	err = writeRestoredFile(dbPath, []byte("new-db-bytes"), ts)
	require.Error(t, err)

	require.NoError(t, os.Chmod(dbDir, 0750))
	info, statErr := os.Stat(dbPath)
	require.NoError(t, statErr)
	require.Zero(t, info.Size(), "target must be left unchanged (still empty) after a failed restore write")
}

// --- test-only archive construction helpers ---

func mustMarshalManifest(t *testing.T, m backupManifest) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	return data
}

type rawEntry struct {
	name     string
	typeflag byte
	data     []byte
}

// writeRawTestArchive writes a gzipped tar with exactly the given entries,
// verbatim -- unlike writeBackupArchive, this can construct archives
// readBackupArchive must reject (wrong first entry, non-regular entries,
// duplicates, entries the manifest doesn't reference, oversized entries).
func writeRawTestArchive(t *testing.T, path string, entries []rawEntry) {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test-controlled path under t.TempDir()
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typeflag
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0600, Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Linkname = string(e.data)
		} else {
			hdr.Size = int64(len(e.data))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if typ != tar.TypeSymlink {
			_, err := tw.Write(e.data)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
}
