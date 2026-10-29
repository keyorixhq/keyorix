package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeOneTableArchive writes a gzip'd tar with a MANIFEST.json and one
// table entry of size bytes (repeated NDJSON lines) to path, and returns the
// entry's real SHA-256. manifestSHA overrides the declared checksum when set.
func writeOneTableArchive(t *testing.T, path string, size int, manifestSHA string) string {
	t.Helper()
	line := []byte(`{"ID":1,"Name":"` + string(bytes.Repeat([]byte("x"), 100)) + `"}` + "\n")
	h := sha256.New()
	for written := 0; written < size; written += len(line) {
		h.Write(line[:min(len(line), size-written)])
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if manifestSHA == "" {
		manifestSHA = sum
	}
	const tarName = "tables/big.ndjson"
	m, err := json.Marshal(Manifest{FormatVersion: FormatVersion, Backend: Backend, Tables: []TableEntry{{
		Name: "big", TarName: tarName, UncompressedSize: int64(size), SHA256: manifestSHA,
	}}})
	require.NoError(t, err)

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "MANIFEST.json", Mode: 0600, Size: int64(len(m)), Typeflag: tar.TypeReg}))
	_, err = tw.Write(m)
	require.NoError(t, err)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: tarName, Mode: 0600, Size: int64(size), Typeflag: tar.TypeReg}))
	for written := 0; written < size; written += len(line) {
		_, err = tw.Write(line[:min(len(line), size-written)])
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return sum
}

// TestExtractArchive_StreamsTableEntries (#3462): staging a table entry must
// not hold the entry in memory. Before the fix readCapped io.ReadAll'd each
// entry (a whole table's NDJSON, up to 1 GiB), so restore's peak memory grew
// with the largest table; this extraction then allocated more than the entry
// itself. Now it streams through the hash into the staged file, and the
// allocations stay a small constant (gzip/tar state and copy buffers).
func TestExtractArchive_StreamsTableEntries(t *testing.T) {
	const entrySize = 16 << 20
	archive := filepath.Join(t.TempDir(), "big.tar.gz")
	sum := writeOneTableArchive(t, archive, entrySize, "")
	stagingDir := t.TempDir()

	f, err := os.Open(archive)
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err = ExtractArchive(f, stagingDir, 0, 0)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)

	allocated := after.TotalAlloc - before.TotalAlloc
	require.Less(t, allocated, uint64(entrySize/4),
		"extracting a %d-byte entry allocated %d bytes: the entry is being buffered in memory", entrySize, allocated)

	staged, err := os.Open(filepath.Join(stagingDir, "tables", "big.ndjson"))
	require.NoError(t, err)
	defer staged.Close() //nolint:errcheck
	h := sha256.New()
	_, err = staged.WriteTo(h)
	require.NoError(t, err)
	require.Equal(t, sum, hex.EncodeToString(h.Sum(nil)))
}

// TestExtractArchive_RefusedEntryLeavesNoStagedFile: a checksum mismatch is
// refused as before, and the streamed partial file is removed.
func TestExtractArchive_RefusedEntryLeavesNoStagedFile(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.tar.gz")
	writeOneTableArchive(t, archive, 64<<10, hex.EncodeToString(make([]byte, 32)))
	stagingDir := t.TempDir()
	f, err := os.Open(archive)
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck

	_, err = ExtractArchive(f, stagingDir, 0, 0)
	require.ErrorContains(t, err, "checksum mismatch")
	_, statErr := os.Stat(filepath.Join(stagingDir, "tables", "big.ndjson"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
