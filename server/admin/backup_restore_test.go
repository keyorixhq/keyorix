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

// writeBackupArchive/writeBackupArchiveContents/writeTarEntry are v1's
// original archive WRITER (#2099) -- production code no longer calls this
// (backup.go writes only the v2 logical format now, design §3.6 decision
// 6), but readBackupArchive's own defensive-parsing tests (this file,
// backup_restore_rollback_test.go, backup_restore_fuzz_test.go) still need
// a real v1-shaped archive to feed it. Kept here, test-only, purely as
// fixture-construction support for the v1 reader this package still ships.
func writeBackupArchive(outputPath string, manifest backupManifest, dbBytes []byte, keyBlobs [][]byte) error {
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- test-only fixture writer
	if err != nil {
		return err
	}
	if err := writeBackupArchiveContents(f, manifest, dbBytes, keyBlobs); err != nil {
		_ = f.Close()
		_ = os.Remove(outputPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(outputPath)
		return err
	}
	return nil
}

func writeBackupArchiveContents(f *os.File, manifest backupManifest, dbBytes []byte, keyBlobs [][]byte) error {
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTarEntry(tw, "MANIFEST.json", manifestJSON); err != nil {
		return err
	}
	if err := writeTarEntry(tw, manifest.DBFile.TarName, dbBytes); err != nil {
		return err
	}
	for i, blob := range keyBlobs {
		if err := writeTarEntry(tw, manifest.KeyFiles[i].TarName, blob); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
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
	require.NoError(t, os.Chmod(dbDir, 0500))           // read+execute only: no new files can be created
	t.Cleanup(func() { _ = os.Chmod(dbDir, 0750) })     // let t.TempDir() clean up afterward

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

// TestWriteRestoredFileSet_AllSucceed_InstallsEveryFile is the green case:
// every file in a multi-file set installs, each with the same guarantees
// (0600, correct content) a single writeRestoredFile call gives.
func TestWriteRestoredFileSet_AllSucceed_InstallsEveryFile(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "salt.key"),
		filepath.Join(dir, "dek.key"),
		filepath.Join(dir, "provider.key"),
	}
	data := [][]byte{[]byte("salt-bytes"), []byte("dek-bytes"), []byte("provider-bytes")}

	require.NoError(t, writeRestoredFileSet(paths, data, "20260101T000000Z"))

	for i, p := range paths {
		got, err := os.ReadFile(p)
		require.NoError(t, err)
		require.Equal(t, string(data[i]), string(got))
		info, statErr := os.Stat(p)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(restoreFileMode), info.Mode().Perm())
	}
}

// TestWriteRestoredFileSet_PrepareFailureLeavesNothingInstalled is the
// red/green proof for the atomicity gap this set-install replaces: the
// previous code called writeRestoredFile for each key file in a simple
// loop, so a failure partway through (file 1 OK, file 2 fails) left file 1
// ALREADY INSTALLED on disk -- a partial, broken key-material set, and
// (without --overwrite-existing) a retry would then fail on file 1's own
// refuseNonEmptyExisting preflight check, since it's no longer empty.
//
// writeRestoredFileSet runs every file's PREPARE phase (write+fsync a temp
// copy, touching nothing at the real target path) to completion before
// installing any of them -- so when file 2's prepare fails here, file 1 must
// NOT exist at its target path at all, proving a retry would see a clean
// target directory, not a partial one.
func TestWriteRestoredFileSet_PrepareFailureLeavesNothingInstalled(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	goodPath := filepath.Join(dir, "salt.key")

	// blocker is a FILE, not a directory -- os.MkdirAll(filepath.Dir(badPath), ...)
	// fails because a path component that must be a directory already
	// exists as a regular file, deterministically failing badPath's
	// prepareRestoredFile without touching the filesystem outside blocker
	// itself (which pre-existed, not something this call created).
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not-a-directory"), 0600))
	badPath := filepath.Join(blocker, "dek.key")

	err := writeRestoredFileSet(
		[]string{goodPath, badPath},
		[][]byte{[]byte("salt-bytes"), []byte("dek-bytes")},
		"20260101T000000Z",
	)
	require.Error(t, err)

	_, statErr := os.Stat(goodPath)
	require.True(t, os.IsNotExist(statErr),
		"goodPath must NOT exist after a later file's prepare fails -- "+
			"this is the whole point of preparing the entire set before committing any of it; got stat err: %v", statErr)
}

// TestWriteRestoredFileSet_CommitFailureCanStillLeavePartialInstall is the
// honest counterpart to the test above: this guard narrows the unsafe
// window, it does not close it. If a LATER file's COMMIT (not prepare)
// fails, an earlier file in the set can still end up installed -- true
// cross-file atomicity would need a filesystem transaction this code
// doesn't have. The remaining window is just the commit loop's fast
// rename/link syscalls, not the full write+fsync+rename cycle the old
// per-file loop risked for every file.
func TestWriteRestoredFileSet_CommitFailureCanStillLeavePartialInstall(t *testing.T) {
	resetRestoreOverwriteFlag(t)
	restoreOverwriteExisting = false

	dir := t.TempDir()
	goodPath := filepath.Join(dir, "salt.key")

	// badPath pre-exists, non-empty -- prepareRestoredFile doesn't check
	// target existence at all (only commitRestoredFile's own concurrent-
	// creation re-check does), so its prepare phase succeeds; only its
	// commit fails, exactly like something else occupying the path mid-
	// restore (TestWriteRestoredFile_NoOverwrite_RefusesConcurrentNonEmptyFile's
	// single-file case).
	badPath := filepath.Join(dir, "dek.key")
	require.NoError(t, os.WriteFile(badPath, []byte("someone-else-wrote-this"), 0600))

	err := writeRestoredFileSet(
		[]string{goodPath, badPath},
		[][]byte{[]byte("salt-bytes"), []byte("dek-bytes")},
		"20260101T000000Z",
	)
	require.Error(t, err)

	got, readErr := os.ReadFile(goodPath)
	require.NoError(t, readErr, "a commit failure on a LATER file in the set does not roll back an EARLIER file already committed -- documented, not silently assumed away")
	require.Equal(t, "salt-bytes", string(got))
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
