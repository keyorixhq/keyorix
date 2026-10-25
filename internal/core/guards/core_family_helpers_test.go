package guards

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// coreFamilySources is how a guard in this package lists "every core source
// file" (ADR-121 R5): the non-test .go files of internal/core plus every
// package extracted from it (srcpath.CoreFamilyGoFiles), as absolute paths.
// Use srcpath.CoreFamilyRel for the "file.go" keys allowlists use.
// TestNoAdHocCoreDirListing fails on a guard that lists internal/core itself.
func coreFamilySources(t testing.TB) []string {
	t.Helper()
	files, err := srcpath.CoreFamilyGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 50 {
		t.Fatalf("only %d core family source files: wrong root", len(files))
	}
	return files
}

// writeTree writes files (slash-separated paths relative to root) for a
// synthetic source tree.
func writeTree(t testing.TB, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
