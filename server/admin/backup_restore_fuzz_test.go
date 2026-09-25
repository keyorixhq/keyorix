package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadBackupArchive is the #2099 review's item 6 fuzz target: restore
// reads an operator-supplied archive that may come from untrusted or
// removable media, so readBackupArchive must never panic on malformed input,
// and must never allocate more than the caps it's given regardless of what
// the input claims to decompress to. The caps passed here are deliberately
// tiny -- this exercises "bounded allocation" directly (a cap that were
// silently bypassed would show up as this fuzz run stalling/OOMing, not
// merely as a wrong error), not just an inference from reading the code.
func FuzzReadBackupArchive(f *testing.F) {
	valid := fuzzSeedValidArchive(f)
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("not a gzip archive at all"))
	f.Add([]byte{0x1f, 0x8b}) // gzip magic bytes, nothing else

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "fuzz-archive.tar.gz")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Skip()
		}
		_, _, _, _ = readBackupArchive(path, 64<<10, 256<<10)
	})
}

func fuzzSeedValidArchive(f *testing.F) []byte {
	f.Helper()
	dbData := []byte("seed-db-bytes")
	keyData := [][]byte{[]byte("seed-key-bytes")}
	manifest := buildTestManifest(dbData, keyData)

	path := filepath.Join(f.TempDir(), "seed-valid.tar.gz")
	if err := writeBackupArchive(path, manifest, dbData, keyData); err != nil {
		f.Fatalf("build seed archive: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Fatalf("read seed archive: %v", err)
	}
	return data
}
