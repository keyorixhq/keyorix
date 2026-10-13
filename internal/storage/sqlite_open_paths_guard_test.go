package storage

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

// sqliteOpenAllowlist lists the production files allowed to open a SQLite handle
// WITHOUT openSQLiteGorm's write gate, each with its reason. Every entry must open
// read-only (mode=ro): a read-only handle cannot take the write lock, so the gate
// has nothing to serialize. sqlite_write_gate.go is the gate itself.
var sqliteOpenAllowlist = map[string]string{
	"internal/storage/sqlite_write_gate.go": "openSQLiteGorm: the gated open every production write path uses",
	"server/admin/restore.go":               "read-only (mode=ro) inspection of a backup/restore artifact",
	"internal/auditverify/db.go":            "read-only (mode=ro) audit-chain verification of an artifact",
}

// TestSQLiteOpenPaths_AllGoThroughTheWriteGate is the structural half of the #2630
// guard. TestSQLite_ConcurrentDistinctSecretWrites_SucceedOrFailFast proves the
// gate works on the path it exercises; this proves there is no other production
// path. It walks every non-test .go file in the module and flags any call that opens
// a SQLite database (sqlitedialect.Open / sqlitedialect.New, or database/sql's
// sql.Open with the "sqlite" driver) outside the allowlist.
//
// Recognised call forms (the complete set of ways this module can open SQLite: the
// only SQLite driver is modernc.org/sqlite, registered as "sqlite", and the only
// GORM dialector is internal/storage/sqlitedialect): <alias>.Open(...) and
// <alias>.New(...) where <alias> is however the file imports sqlitedialect, and
// <alias>.Open("sqlite", ...) or <alias>.Open(<dialect>.DriverName, ...) where
// <alias> is database/sql. NOT recognised:
// sql.OpenDB with a hand-built connector, or a driver name passed through a
// variable. Neither appears in the module today. Skipped directories: examples/
// (sample programs), internal/testhelper and internal/testutil (test fixtures),
// and sqlitedialect itself.
func TestSQLiteOpenPaths_AllGoThroughTheWriteGate(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	skipDirs := map[string]bool{"examples": true, "internal/testhelper": true, "internal/testutil": true,
		"internal/storage/sqlitedialect": true, "node_modules": true, "web": true, ".git": true}
	found := map[string][]string{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDirs[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if sites := sqliteOpenCalls(t, path); len(sites) > 0 {
			found[rel] = append(found[rel], sites...)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var offenders []string
	for file, sites := range found {
		if _, ok := sqliteOpenAllowlist[file]; !ok {
			offenders = append(offenders, file+": "+strings.Join(sites, ", "))
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("SQLite opened outside the write gate (use openSQLiteGorm, or open read-only and add a reasoned allowlist entry):\n  %s",
			strings.Join(offenders, "\n  "))
	}

	// Premise checks, both directions: every allowlisted file still opens SQLite
	// (no stale entries), and every read-only entry really is read-only.
	for file, reason := range sqliteOpenAllowlist {
		if len(found[file]) == 0 {
			t.Errorf("allowlist entry %s no longer opens SQLite; remove it", file)
		}
		if strings.HasPrefix(reason, "read-only") {
			src, err := os.ReadFile(filepath.Join(root, file))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(src), "mode=ro") {
				t.Errorf("allowlist entry %s claims read-only but has no mode=ro DSN", file)
			}
		}
	}
}

// sqliteOpenCalls returns file:line for every recognised SQLite-open call in path.
func sqliteOpenCalls(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var dialectAlias, sqlAlias string
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch p {
		case "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect":
			dialectAlias = name
			if name == "" {
				dialectAlias = "sqlite" // the package's declared name
			}
		case "database/sql":
			sqlAlias = name
			if name == "" {
				sqlAlias = "sql"
			}
		}
	}
	if dialectAlias == "" && sqlAlias == "" {
		return nil
	}
	f, err = parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch {
		case dialectAlias != "" && x.Name == dialectAlias && (sel.Sel.Name == "Open" || sel.Sel.Name == "New"):
			out = append(out, fset.Position(call.Pos()).String())
		case sqlAlias != "" && x.Name == sqlAlias && sel.Sel.Name == "Open" && len(call.Args) > 0:
			switch a := call.Args[0].(type) {
			case *ast.BasicLit:
				if v, _ := strconv.Unquote(a.Value); v == "sqlite" {
					out = append(out, fset.Position(call.Pos()).String())
				}
			case *ast.SelectorExpr: // sql.Open(sqlitedialect.DriverName, ...)
				if id, ok := a.X.(*ast.Ident); ok && dialectAlias != "" && id.Name == dialectAlias && a.Sel.Name == "DriverName" {
					out = append(out, fset.Position(call.Pos()).String())
				}
			}
		}
		return true
	})
	return out
}
