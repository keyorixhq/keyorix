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
	"strings"
	"testing"
)

// craftArchive builds a gzip'd tar whose MANIFEST.json lists one table entry
// with the given tar name and a self-consistent size/checksum, followed by
// that entry: exactly what an attacker controls before signature checks.
func craftArchive(t testing.TB, tarName string, payload []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(payload)
	m := Manifest{Tables: []TableEntry{{
		Name: "x", TarName: tarName, UncompressedSize: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]),
	}}}
	mj, err := json.Marshal(m)
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

// TestExtractArchive_RefusesPathTraversal: a crafted archive must never write
// outside the staging directory, whatever its (unverified) manifest says.
// Red before the fix: "../escaped.txt" landed one directory above staging.
func TestExtractArchive_RefusesPathTraversal(t *testing.T) {
	for _, name := range []string{
		"../escaped.txt",
		"tables/../../escaped.txt",
		"/tmp/keyorix-tarslip-absolute.txt",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			staging := filepath.Join(root, "staging")
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			payload := []byte("attacker-controlled")
			_, err := ExtractArchive(bytes.NewReader(craftArchive(t, name, payload)), staging, 0, 0)
			if err == nil || !strings.Contains(err.Error(), "not a safe relative path") {
				t.Fatalf("ExtractArchive(%q) err = %v, want a refusal", name, err)
			}
			if _, statErr := os.Stat(filepath.Join(root, "escaped.txt")); statErr == nil {
				t.Fatalf("payload escaped the staging directory for %q", name)
			}
			if filepath.IsAbs(name) {
				if _, statErr := os.Stat(name); statErr == nil {
					_ = os.Remove(name)
					t.Fatalf("payload was written to absolute path %q", name)
				}
			}
		})
	}
}

// A legitimate nested name still extracts.
func TestExtractArchive_AcceptsLocalNestedName(t *testing.T) {
	staging := t.TempDir()
	if _, err := ExtractArchive(bytes.NewReader(craftArchive(t, "tables/x.ndjson", []byte("{}\n"))), staging, 0, 0); err != nil {
		t.Fatalf("legitimate archive refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, "tables", "x.ndjson")); err != nil {
		t.Fatalf("legitimate entry not staged: %v", err)
	}
}
