package storage

// legacy_service_accounts_writer_guard_test.go — #2541: the static half of the
// api_clients/api_tokens emptiness argument. #552 (v0.87.0) removed every code
// path that inserted into these tables; this keeps it that way.
//
// What it recognises as a writer, in every non-test .go file of the root module:
//   - a composite literal of models.APIClient or models.APIToken (APIClient /
//     APIToken inside package models) with at least one field set: building a
//     row value. An empty literal (&models.APIToken{}) is a table handle for
//     AutoMigrate, Model(...).Count or Model(...).Updates and is not flagged;
//   - a string literal containing INSERT INTO api_clients / api_tokens.
//
// What it does NOT see: generic copies that move existing rows without naming
// the type, which is how backup restore (internal/backupfmt LoadArchive, via
// reflect over storage.AllModels) can bring rows back from an archive that has
// them; the I6 old-release fixtures do (scripts/i6-gen). Rows built through
// reflect or a map passed to Table("api_tokens").Create are not recognised
// either. The cli/ and operator/ modules are not walked: neither imports
// internal/storage/models.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var legacySAInsertSQL = regexp.MustCompile(`(?i)insert\s+into\s+["` + "`" + `]?api_(clients|tokens)\b`)

// legacySAWriters returns one finding per writer shape in a parsed file.
func legacySAWriters(fset *token.FileSet, f *ast.File) []string {
	modelsAlias := ""
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p == "github.com/keyorixhq/keyorix/internal/storage/models" {
			modelsAlias = "models"
			if imp.Name != nil {
				modelsAlias = imp.Name.Name
			}
		}
	}
	inModels := f.Name.Name == "models"
	isLegacy := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && modelsAlias != "" && id.Name == modelsAlias && (x.Sel.Name == "APIClient" || x.Sel.Name == "APIToken")
		case *ast.Ident:
			return inModels && (x.Name == "APIClient" || x.Name == "APIToken")
		}
		return false
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if x.Type != nil && isLegacy(x.Type) && len(x.Elts) > 0 {
				out = append(out, fset.Position(x.Pos()).String()+": builds a legacy service-account row")
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && legacySAInsertSQL.MatchString(x.Value) {
				out = append(out, fset.Position(x.Pos()).String()+": INSERT into a legacy service-account table")
			}
		}
		return true
	})
	return out
}

func TestNoLiveWriterForLegacyServiceAccountTables(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found at %s: %v", root, err)
	}
	skipDirs := map[string]bool{"cli": true, "operator": true, "web": true, "node_modules": true, "vendor": true, "testdata": true, ".git": true, ".scratch": true}
	fset := token.NewFileSet()
	files := 0
	var findings []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		findings = append(findings, legacySAWriters(fset, f)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Population floor: a walk that found almost nothing would pass vacuously.
	if files < 500 {
		t.Fatalf("walked only %d non-test Go files under %s; the walk is broken", files, root)
	}
	t.Logf("VERIFY static: %d non-test Go files walked, %d legacy service-account writers", files, len(findings))
	for _, f := range findings {
		t.Errorf("%s (api_clients/api_tokens must stay write-free until #2541 removes them)", f)
	}
}

// TestLegacySAWriterGuard_Calibration: the detector flags each writer shape and
// passes the table-handle shapes production uses.
func TestLegacySAWriterGuard_Calibration(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"row literal", `package x
import "github.com/keyorixhq/keyorix/internal/storage/models"
var _ = models.APIToken{Token: "h"}`, 1},
		{"aliased row literal", `package x
import m "github.com/keyorixhq/keyorix/internal/storage/models"
var _ = &m.APIClient{ClientID: "c"}`, 1},
		{"in package models", `package models
var _ = APIClient{Name: "n"}`, 1},
		{"raw insert", "package x\nconst q = `INSERT INTO api_tokens (token) VALUES (?)`", 1},
		{"table handles only", `package x
import "github.com/keyorixhq/keyorix/internal/storage/models"
var _ = []any{&models.APIClient{}, &models.APIToken{}}
const q = "SELECT COUNT(*) FROM api_tokens"`, 0},
	}
	for _, tc := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := len(legacySAWriters(fset, f)); got != tc.want {
			t.Errorf("%s: %d findings, want %d", tc.name, got, tc.want)
		}
	}
}
