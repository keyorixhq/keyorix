package sqlitetest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestFactoryConfigsNeverUseSharedCacheDSN fails when a test hands DSN (a shared-cache
// in-memory database) to the production storage factory as a database.path: the
// factory's multi-connection pool on a shared cache fails writes with SQLITE_LOCKED
// (262) whenever another connection holds a read lock on the table, past any busy
// timeout (see FactoryPath). Such a config must use FactoryPath.
//
// What it recognises: `Path: sqlitetest.DSN(...)` in a composite literal (the
// config.DatabaseConfig shape every such test used) and `x.Path = sqlitetest.DSN(...)`.
// What it does not: a DSN first stored in a variable, or passed through a helper,
// before it reaches a Path field.
//
// factoryDSNAllowed are the files that hand DSN to the factory on purpose; an entry
// whose file no longer does so fails, so the list cannot go stale.
var factoryDSNAllowed = map[string]string{
	"internal/storage/storage_s27_test.go": "TestCreateLocalStorage_S27_ExistingDSNQueryString: the database.path under test IS a DSN with a query string; one storage, no concurrent use",
}

func TestFactoryConfigsNeverUseSharedCacheDSN(t *testing.T) {
	root := repoRoot(t)
	var bad []string
	allowedSeen := map[string]bool{}
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- a .go file of this repository, found by the walk
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), "sqlitetest.DSN(") {
			return nil
		}
		scanned++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, line := range dsnAsFactoryPathLines(t, path, src) {
			if _, ok := factoryDSNAllowed[rel]; ok {
				allowedSeen[rel] = true
				continue
			}
			bad = append(bad, rel+":"+line)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned < 5 {
		t.Fatalf("found sqlitetest.DSN( in only %d files: the walk is looking in the wrong place", scanned)
	}
	for f := range factoryDSNAllowed {
		if !allowedSeen[f] {
			bad = append(bad, f+": in factoryDSNAllowed but no longer hands DSN to a Path; remove the entry")
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("a shared-cache DSN is handed to the storage factory as database.path; use sqlitetest.FactoryPath "+
			"(a file, the production shape) — the factory's pool on a shared cache fails writes with "+
			"\"database table is locked (262)\":\n  %s", strings.Join(bad, "\n  "))
	}
}

func TestDSNAsFactoryPathLines_Calibration(t *testing.T) {
	src := []byte(`package x
var a = config.DatabaseConfig{Path: sqlitetest.DSN("a_")}
func f() {
	cfg.Storage.Database.Path = sqlitetest.DSN("b_")
	ok := config.DatabaseConfig{Path: sqlitetest.FactoryPath(t, "c_")}
	db := openLoginBudgetDB(t, sqlitetest.DSN("d_"))
	_, _ = ok, db
}
`)
	got := dsnAsFactoryPathLines(t, "calibration.go", src)
	if strings.Join(got, ",") != "2,4" {
		t.Fatalf("want lines 2 and 4 (the two Path shapes), got %v", got)
	}
}

// dsnAsFactoryPathLines returns the lines where sqlitetest.DSN(...) is the value of a
// Path field (composite literal key or assignment to a .Path selector).
func dsnAsFactoryPathLines(t *testing.T, filename string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	isDSN := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "DSN" {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "sqlitetest"
	}
	var lines []string
	add := func(p token.Pos) { lines = append(lines, strconv.Itoa(fset.Position(p).Line)) }
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.KeyValueExpr:
			if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Path" && isDSN(n.Value) {
				add(n.Pos())
			}
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Path" && i < len(n.Rhs) && isDSN(n.Rhs[i]) {
					add(n.Pos())
				}
			}
		}
		return true
	})
	return lines
}
