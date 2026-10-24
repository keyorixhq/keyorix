package srcpath

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCoreFamilyGoFiles_SeesEveryFamilyDir is the coverage half of R5 for the
// shared lister: a directory added to the family shows up in CoreFamilyGoFiles
// (its non-test files only, not its subdirectories), every non-test file of
// internal/core is listed, and the extra directory is gone after the test.
func TestCoreFamilyGoFiles_SeesEveryFamilyDir(t *testing.T) {
	coreDir := filepath.Join(RepoRoot(), filepath.FromSlash(CoreDir))
	if dirs := CoreFamilyDirs(); len(dirs) == 0 || dirs[0] != coreDir {
		t.Fatalf("CoreFamilyDirs()[0] must be %s, got %v", coreDir, dirs)
	}

	extra := t.TempDir()
	for name, body := range map[string]string{
		"leaf.go":      "package leaf\n",
		"leaf_test.go": "package leaf\n",
		"sub/inner.go": "package sub\n",
		"notes.txt":    "not go\n",
	} {
		p := filepath.Join(extra, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("with extra dir", func(t *testing.T) {
		AddCoreFamilyDirForTesting(t, extra)
		files, err := CoreFamilyGoFiles()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(files, filepath.Join(extra, "leaf.go")) {
			t.Errorf("a registered family dir's file is missing from CoreFamilyGoFiles")
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || strings.HasPrefix(f, filepath.Join(extra, "sub")) || !strings.HasSuffix(f, ".go") {
				t.Errorf("CoreFamilyGoFiles listed %s: only non-test .go files directly in a family dir belong", f)
			}
		}
		entries, err := os.ReadDir(coreDir)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			n++
			if !slices.Contains(files, filepath.Join(coreDir, name)) {
				t.Errorf("internal/core/%s is missing from CoreFamilyGoFiles", name)
			}
		}
		if n < 50 {
			t.Fatalf("only %d non-test files in %s: wrong root", n, coreDir)
		}
	})

	files, err := CoreFamilyGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(files, filepath.Join(extra, "leaf.go")) {
		t.Error("AddCoreFamilyDirForTesting must remove its dir when the test ends")
	}
}

func TestRegisterCoreFamilyDir_RejectsBadEntries(t *testing.T) {
	saved := coreFamilyExtracted
	coreFamilyExtracted = map[string]string{}
	t.Cleanup(func() { coreFamilyExtracted = saved })

	registerCoreFamilyDir("internal/anomaly", "pilot")
	if got := CoreFamilyExtractedDirs(); !slices.Equal(got, []string{"internal/anomaly"}) {
		t.Fatalf("CoreFamilyExtractedDirs = %v", got)
	}
	if dirs := CoreFamilyDirs(); dirs[1] != filepath.Join(RepoRoot(), "internal", "anomaly") {
		t.Fatalf("a registered dir must follow internal/core in CoreFamilyDirs: %v", dirs)
	}
	for _, bad := range []struct{ rel, reason string }{
		{"internal/anomaly", "again"},  // duplicate
		{CoreDir, "core itself"},       // not an extraction
		{"/abs/dir", "absolute"},       // not repository-relative
		{"internal/x/../y", "unclean"}, // not clean
		{"../outside", "outside"},      // escapes the repo
		{"internal/z", ""},             // no reason
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("registerCoreFamilyDir(%q, %q) must panic", bad.rel, bad.reason)
				}
			}()
			registerCoreFamilyDir(bad.rel, bad.reason)
		}()
	}
}

func TestCoreFamilyRel(t *testing.T) {
	root := RepoRoot()
	for path, want := range map[string]string{
		filepath.Join(root, "internal", "core", "secrets.go"):        "secrets.go",
		filepath.Join(root, "internal", "core", "rules", "scope.go"): "internal/core/rules/scope.go",
		filepath.Join(root, "internal", "anomaly", "forest.go"):      "internal/anomaly/forest.go",
	} {
		if got := CoreFamilyRel(path); got != want {
			t.Errorf("CoreFamilyRel(%s) = %q, want %q", path, got, want)
		}
	}
}
