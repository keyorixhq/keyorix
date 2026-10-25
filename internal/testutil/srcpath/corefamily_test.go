package srcpath

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
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

// TestCoreFamilyRegistry_Rows pins the committed rows: the core row is
// internal/core and the test-only packages are the two ADR-121 creates. The
// literals live here, in a _test.go file, on purpose (corefamily.d/README.md).
func TestCoreFamilyRegistry_Rows(t *testing.T) {
	if CoreDir != "internal/core" {
		t.Errorf("CoreDir = %q, want internal/core", CoreDir)
	}
	if want := []string{"internal/core/coretests", "internal/core/storage/storagetest"}; !slices.Equal(CoreTestOnlyDirs, want) {
		t.Errorf("CoreTestOnlyDirs = %v, want %v", CoreTestOnlyDirs, want)
	}
	for _, rel := range CoreFamilyExtractedDirs() {
		if !strings.HasPrefix(rel, "internal/") {
			t.Errorf("extracted dir %s is outside internal/", rel)
		}
	}
}

func TestLoadCoreFamily_RejectsBadEntries(t *testing.T) {
	const core = "core\tinternal/core\tthe package\n"
	good := fstest.MapFS{
		"d/core.tsv":    {Data: []byte("# kind\tdir\treason\n" + core)},
		"d/anomaly.tsv": {Data: []byte("extracted\tinternal/anomaly\tpilot\n")},
		"d/kit.tsv":     {Data: []byte("testonly\tinternal/core/coretests\tdecision 2\n")},
		"d/README.md":   {Data: []byte("not a row\n")},
	}
	reg, err := loadCoreFamily(good, "d")
	if err != nil {
		t.Fatal(err)
	}
	if reg.core != "internal/core" || reg.extracted["internal/anomaly"] != "pilot" || !slices.Equal(reg.testOnly, []string{"internal/core/coretests"}) {
		t.Fatalf("loadCoreFamily = %+v", reg)
	}

	for name, files := range map[string]map[string]string{
		"empty dir":         {},
		"no core row":       {"a.tsv": "extracted\tinternal/a\tx\n"},
		"two core rows":     {"a.tsv": core, "b.tsv": "core\tinternal/b\tx\n"},
		"two rows one file": {"a.tsv": core + "extracted\tinternal/b\tx\n"},
		"no rows":           {"a.tsv": core, "b.tsv": "# only a comment\n"},
		"duplicate dir":     {"a.tsv": core, "b.tsv": "extracted\tinternal/core\tagain\n"},
		"duplicate leaf":    {"a.tsv": core, "b.tsv": "extracted\tinternal/x\t1\n", "c.tsv": "testonly\tinternal/x\t2\n"},
		"no reason":         {"a.tsv": core, "b.tsv": "extracted\tinternal/x\t\n"},
		"two fields":        {"a.tsv": core, "b.tsv": "extracted\tinternal/x\n"},
		"four fields":       {"a.tsv": core, "b.tsv": "extracted\tinternal/x\ty\tz\n"},
		"unknown kind":      {"a.tsv": core, "b.tsv": "moved\tinternal/x\ty\n"},
		"absolute":          {"a.tsv": core, "b.tsv": "extracted\t/abs/dir\ty\n"},
		"unclean":           {"a.tsv": core, "b.tsv": "extracted\tinternal/x/../y\ty\n"},
		"outside":           {"a.tsv": core, "b.tsv": "extracted\t../outside\ty\n"},
		"backslash":         {"a.tsv": core, "b.tsv": "extracted\tinternal\\\\x\ty\n"},
	} {
		fsys := fstest.MapFS{"d/README.md": {Data: []byte("x")}}
		for f, body := range files {
			fsys["d/"+f] = &fstest.MapFile{Data: []byte(body)}
		}
		if _, err := loadCoreFamily(fsys, "d"); err == nil {
			t.Errorf("%s: loadCoreFamily must fail", name)
		}
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
