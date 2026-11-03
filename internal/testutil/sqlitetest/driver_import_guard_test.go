// driver_import_guard_test.go keeps new tests off gorm.io/driver/sqlite unless
// the file is on driver_import_allowlist.tsv with a reason (SQLITE-FIDELITY-1,
// #3685).
//
// Production opens SQLite through internal/storage/sqlitedialect (modernc plus
// the repo's error translator and migrator). A test that opens gorm.io/driver/sqlite
// instead runs a different driver with different error values, so a claim that
// depends on how a storage error is translated, on a constraint, or on locking
// can stay green while production differs. Tests that need an in-memory SQLite
// open it through sqlitetest.Open (schema-only and pure-logic tests) or
// sqlitetest.OpenWithDialector with sqlitedialect.Open (everything else).
//
// What it recognises: an import of "gorm.io/driver/sqlite" (any alias, or a
// blank or dot import) in a *_test.go file anywhere in the repository, found
// with go/parser, so comments and string literals that mention the path do not
// count. What it does not: a driver reached through a helper in a non-test file
// (internal/testutil/sqlitetest itself imports it, deliberately), or a test
// that imports the driver's sub-packages. The guard says nothing about whether
// an allowlisted file SHOULD be on the production dialect; the reason column
// is where that judgement is written down.
//
// Rollout: report-only (docs/guard-rollout.d/TestNoNewDriverSqliteTestImports.tsv).
package sqlitetest

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

const driverImportPath = "gorm.io/driver/sqlite"

const driverImportAllowlistFile = "driver_import_allowlist.tsv"

// importsDriver reports whether src, a Go file, imports driverImportPath.
func importsDriver(filename string, src []byte) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == driverImportPath {
			return true, nil
		}
	}
	return false, nil
}

// testFilesImportingDriver returns the repo-relative, slash-separated path of
// every *_test.go file under root that imports the driver, and the files it
// could not parse (a guard that skips what it cannot read says so).
func testFilesImportingDriver(root string) (found, unparsable []string, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walks the repository
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), driverImportPath) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		ok, perr := importsDriver(path, src)
		switch {
		case perr != nil:
			unparsable = append(unparsable, rel)
		case ok:
			found = append(found, rel)
		}
		return nil
	})
	slices.Sort(found)
	slices.Sort(unparsable)
	return found, unparsable, err
}

// parseDriverAllowlist reads "path<TAB>reason" rows; blank lines and lines
// starting with '#' are skipped. A row without a reason, or a path listed twice,
// is returned in problems.
func parseDriverAllowlist(data string) (rows map[string]string, problems []string) {
	rows = map[string]string{}
	for i, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, reason, ok := strings.Cut(line, "\t")
		path, reason = strings.TrimSpace(path), strings.TrimSpace(reason)
		switch {
		case !ok || path == "" || reason == "":
			problems = append(problems, fmt.Sprintf("line %d: want \"<path>\\t<one-line reason>\"", i+1))
		case !strings.HasSuffix(path, "_test.go"):
			problems = append(problems, fmt.Sprintf("line %d: %s is not a _test.go file", i+1, path))
		default:
			if _, dup := rows[path]; dup {
				problems = append(problems, fmt.Sprintf("line %d: %s is listed twice", i+1, path))
			}
			rows[path] = reason
		}
	}
	return rows, problems
}

// driverImportFindings compares the importers found with the allowlist.
// unlisted: imports the driver, not on the list. stale: on the list, no longer
// imports it (the list only shrinks).
func driverImportFindings(found []string, allow map[string]string) (unlisted, stale []string) {
	for _, p := range found {
		if _, ok := allow[p]; !ok {
			unlisted = append(unlisted, p)
		}
	}
	for p := range allow {
		if !slices.Contains(found, p) {
			stale = append(stale, p)
		}
	}
	slices.Sort(stale)
	return unlisted, stale
}

func readDriverAllowlist(t testing.TB) (map[string]string, []string) {
	t.Helper()
	data, err := os.ReadFile(driverImportAllowlistFile)
	if err != nil {
		t.Fatalf("read %s: %v", driverImportAllowlistFile, err)
	}
	return parseDriverAllowlist(string(data))
}

// TestNoNewDriverSqliteTestImports is the guard: a test file that imports
// gorm.io/driver/sqlite and is not on the allowlist fails, and so does an
// allowlist entry that no longer imports it or has no reason.
func TestNoNewDriverSqliteTestImports(t *testing.T) {
	g := guardrules.Rollout(t)
	allow, problems := readDriverAllowlist(t)
	for _, p := range problems {
		g.Errorf("%s: %s", driverImportAllowlistFile, p)
	}
	found, unparsable, err := testFilesImportingDriver(repoRoot(t))
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	for _, p := range unparsable {
		g.Errorf("%s mentions %s but its imports do not parse; the guard cannot tell whether it imports the driver", p, driverImportPath)
	}
	unlisted, stale := driverImportFindings(found, allow)
	if len(unlisted) > 0 {
		g.Errorf("test file(s) import %s, the driver production does not run on. Open the database with "+
			"sqlitetest.OpenWithDialector(t, prefix, sqlitedialect.Open, cfg) (or sqlitetest.Open when the test is schema-only), "+
			"or add the file to internal/testutil/sqlitetest/%s with a one-line reason:\n  %s",
			driverImportPath, driverImportAllowlistFile, strings.Join(unlisted, "\n  "))
	}
	if len(stale) > 0 {
		g.Errorf("%s lists file(s) that no longer import %s; remove them so the allowlist only shrinks:\n  %s",
			driverImportAllowlistFile, driverImportPath, strings.Join(stale, "\n  "))
	}
}

// TestDriverImportScan_CalibratedBothWays plants a file that imports the driver
// (red: reported unlisted), then lists it (green), and checks the matcher on
// the import shapes and non-shapes. Without this the guard could pass because
// the scan finds nothing.
func TestDriverImportScan_CalibratedBothWays(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a/planted_test.go", "package a\n\nimport (\n\t\"gorm.io/driver/sqlite\"\n)\n\nvar _ = sqlite.Open\n")
	write("a/aliased_test.go", "package a\n\nimport legacy \"gorm.io/driver/sqlite\"\n\nvar _ = legacy.Open\n")
	write("a/comment_only_test.go", "package a\n\n// gorm.io/driver/sqlite is what this does not import.\nvar s = \"gorm.io/driver/sqlite\"\n")
	write("a/helper.go", "package a\n\nimport \"gorm.io/driver/sqlite\"\n\nvar _ = sqlite.Open\n")
	write("a/testdata/fixture_test.go", "package a\n\nimport \"gorm.io/driver/sqlite\"\n")
	write("a/broken_test.go", "package a\n\nimport \"gorm.io/driver/sqlite\"\nimport (\n")

	found, unparsable, err := testFilesImportingDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a/aliased_test.go", "a/planted_test.go"}; !slices.Equal(found, want) {
		t.Fatalf("found = %v, want %v (planted and aliased imports; not the comment, the non-test file or testdata)", found, want)
	}
	if want := []string{"a/broken_test.go"}; !slices.Equal(unparsable, want) {
		t.Fatalf("unparsable = %v, want %v", unparsable, want)
	}

	// Red: the planted files are not on the real allowlist.
	real, _ := readDriverAllowlist(t)
	unlisted, _ := driverImportFindings(found, real)
	if !slices.Equal(unlisted, found) {
		t.Fatalf("unlisted = %v, want both planted files", unlisted)
	}
	// Green: listed, they pass; an entry for a file that does not import it is stale.
	listed := map[string]string{"a/aliased_test.go": "r", "a/planted_test.go": "r", "a/gone_test.go": "r"}
	unlisted, stale := driverImportFindings(found, listed)
	if len(unlisted) != 0 || !slices.Equal(stale, []string{"a/gone_test.go"}) {
		t.Fatalf("unlisted = %v, stale = %v; want none unlisted and a/gone_test.go stale", unlisted, stale)
	}
}

func TestParseDriverAllowlist_RejectsRowsWithoutAReason(t *testing.T) {
	rows, problems := parseDriverAllowlist("# c\n\na_test.go\tbecause\nb_test.go\t\nc_test.go\nd.go\twhy\na_test.go\tagain\n")
	if len(rows) != 1 || rows["a_test.go"] != "again" {
		t.Fatalf("rows = %v", rows)
	}
	if len(problems) != 4 { // b (empty reason), c (no tab), d.go (not a test file), a (duplicate)
		t.Fatalf("problems = %v, want 4", problems)
	}
	if _, problems := parseDriverAllowlist("a_test.go\tbecause\n"); len(problems) != 0 {
		t.Fatalf("a well-formed row was rejected: %v", problems)
	}
}
