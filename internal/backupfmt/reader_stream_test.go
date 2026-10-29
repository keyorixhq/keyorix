package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestExtractArchive_TableEntryIsStreamed (SCALE-OPS-1): a table's NDJSON entry is as
// large as the table, so extraction must copy it to the staged file through a
// bounded buffer. Before the fix it read the whole entry into a []byte (io.ReadAll
// growing by doubling), so the restore's peak memory grew with the largest table.
func TestExtractArchive_TableEntryIsStreamed(t *testing.T) {
	const size = 16 << 20
	line := []byte(`{"id":1,"event_type":"secret.read","description":"scale line"}` + "\n")
	payload := bytes.Repeat(line, size/len(line))
	archive := craftArchive(t, "tables/audit_events.ndjson", payload)
	staging := t.TempDir()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := ExtractArchive(bytes.NewReader(archive), staging, 0, 0); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(len(payload) / 4); allocated > limit {
		t.Fatalf("extracting a %d-byte table entry allocated %d bytes (limit %d): the entry is being held in memory", len(payload), allocated, limit)
	}
	got, err := os.ReadFile(filepath.Join(staging, "tables", "audit_events.ndjson"))
	if err != nil {
		t.Fatalf("staged table missing: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("staged table differs from the archived one (%d vs %d bytes)", len(got), len(payload))
	}
}

// The streamed path keeps every refusal of the buffered one.
func TestExtractArchive_StreamedEntryKeepsItsChecks(t *testing.T) {
	payload := bytes.Repeat([]byte(`{"id":1}`+"\n"), 1000)

	t.Run("per-entry cap", func(t *testing.T) {
		// the manifest is capped by the same limit, so 4096 passes it and stops the table
		_, err := ExtractArchive(bytes.NewReader(craftArchive(t, "tables/x.ndjson", payload)), t.TempDir(), 4096, 0)
		if err == nil || !strings.Contains(err.Error(), "per-entry limit") {
			t.Fatalf("err = %v, want the manifest-declared per-entry refusal", err)
		}
	})

	t.Run("total cap", func(t *testing.T) {
		_, err := ExtractArchive(bytes.NewReader(craftArchive(t, "tables/x.ndjson", payload)), t.TempDir(), 0, 1024)
		if err == nil || !strings.Contains(err.Error(), "total decompressed size limit") {
			t.Fatalf("err = %v, want the total-size refusal", err)
		}
	})

	t.Run("checksum", func(t *testing.T) {
		bad := craftArchiveWithSum(t, "tables/x.ndjson", payload, strings.Repeat("0", 64))
		_, err := ExtractArchive(bytes.NewReader(bad), t.TempDir(), 0, 0)
		if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("err = %v, want a checksum refusal", err)
		}
	})
}

// craftArchiveWithSum is craftArchive with a manifest that declares sha256Hex for the table.
func craftArchiveWithSum(t testing.TB, tarName string, payload []byte, sha256Hex string) []byte {
	t.Helper()
	mj, err := json.Marshal(Manifest{Tables: []TableEntry{{Name: "x", TarName: tarName, UncompressedSize: int64(len(payload)), SHA256: sha256Hex}}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range []struct {
		name string
		data []byte
	}{{"MANIFEST.json", mj}, {tarName, payload}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
