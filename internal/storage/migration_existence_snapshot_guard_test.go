package storage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// INV-STORAGE-migration-existence-snapshot-before-create guard.
//
// factory.go's migrateDatabase documents one ordering rule that every
// migrate_<domain>.go step depends on: all tableExists queries run in one
// snapshot BEFORE any call that can create a table with AutoMigrate, because a
// creation poisons the pgx prepared-statement cache and a later tableExists can
// then return a spurious false, which re-runs a full AutoMigrate against a
// table that was already column-altered (INV-STORAGE-07).
//
// The test parses the package's non-test files (read only, factory.go is not
// modified), finds every function that reaches AutoMigrate (by callee name,
// transitively: `f()`, `x.f()`), and requires that in migrateDatabase's body
// the last tableExists call comes before the first such call.
//
// What it does not check: that a new step is appended at the END of the list
// (any new step is at the end by construction), that a step's own flag
// parameter came from the snapshot, calls made through function values, or the
// INV-STORAGE-07 rule itself (see that invariant for why it has no guard).
func TestMigrateDatabase_ExistenceSnapshotPrecedesEveryTableCreation(t *testing.T) {
	fset := token.NewFileSet()
	files := parseStoragePkgFiles(t, fset, ".")
	if v := migrationSnapshotOrderViolations(fset, files); len(v) > 0 {
		t.Fatalf("tableExists runs after a table-creating call in migrateDatabase: %s\n"+
			"Add the table's flag to the up-front snapshot (never call tableExists after an AutoMigrate).", strings.Join(v, "; "))
	}
}

func TestMigrationSnapshotOrderDetectsLateExistenceQuery(t *testing.T) {
	const helper = `package storage
func createThing(db *gorm.DB, exists bool) error { return db.AutoMigrate(&models.Thing{}) }
func tableExists(db *gorm.DB, name string) bool { return true }
`
	cases := []struct {
		name, body string
		want       int
	}{
		{"snapshot first", `package storage
func (f *DefaultStorageFactory) migrateDatabase(db *gorm.DB) error {
	a := tableExists(db, "a")
	b := tableExists(db, "b")
	return createThing(db, a && b)
}`, 0},
		{"query after a step that creates", `package storage
func (f *DefaultStorageFactory) migrateDatabase(db *gorm.DB) error {
	a := tableExists(db, "a")
	createThing(db, a)
	b := tableExists(db, "b")
	return createThing(db, b)
}`, 1},
		{"query after a direct AutoMigrate", `package storage
func (f *DefaultStorageFactory) migrateDatabase(db *gorm.DB) error {
	db.AutoMigrate(&models.X{})
	return tableExists(db, "b")
}`, 1},
	}
	old := minSnapshotQueries
	minSnapshotQueries = 0
	defer func() { minSnapshotQueries = old }()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			var files []*ast.File
			for n, src := range map[string]string{"h.go": helper, "f.go": tc.body} {
				f, err := parser.ParseFile(fset, n, src, parser.SkipObjectResolution)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, f)
			}
			got := migrationSnapshotOrderViolations(fset, files)
			for _, v := range got {
				t.Logf("guard would report: %s", v)
			}
			if len(got) != tc.want {
				t.Errorf("got %d violation(s) %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

func parseStoragePkgFiles(t *testing.T, fset *token.FileSet, dir string) []*ast.File {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}

func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func migrationSnapshotOrderViolations(fset *token.FileSet, files []*ast.File) []string {
	funcs := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd)
			}
		}
	}
	calls := func(body ast.Node, set map[string]bool) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && set[calleeName(c)] {
				hit = true
			}
			return !hit
		})
		return hit
	}
	creators := map[string]bool{"AutoMigrate": true}
	for changed := true; changed; {
		changed = false
		for name, decls := range funcs {
			if creators[name] {
				continue
			}
			for _, fd := range decls {
				if calls(fd.Body, creators) {
					creators[name], changed = true, true
					break
				}
			}
		}
	}

	var body *ast.BlockStmt
	for _, fd := range funcs["migrateDatabase"] {
		body = fd.Body
	}
	if body == nil {
		return []string{"migrateDatabase not found: the guard's population is empty"}
	}
	var creates, exists []token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			switch name := calleeName(c); {
			case name == "tableExists":
				exists = append(exists, c.Pos())
			case creators[name]:
				creates = append(creates, c.Pos())
			}
		}
		return true
	})
	// Non-vacuity floor for the real tree (the snapshot holds ~80 queries and
	// many steps); the synthetic self-test sources set minPopulation to 0.
	if len(exists) < minSnapshotQueries || len(creates) < minSnapshotQueries/10 {
		return []string{"migrateDatabase yielded too few tableExists/creating calls: the guard's walk is broken"}
	}
	return lateExistenceQueries(fset, exists, creates)
}

// minSnapshotQueries is the population floor; the self-test lowers it.
var minSnapshotQueries = 20

func lateExistenceQueries(fset *token.FileSet, exists, creates []token.Pos) []string {
	if len(creates) == 0 {
		return nil
	}
	first := creates[0]
	for _, p := range creates {
		if p < first {
			first = p
		}
	}
	var out []string
	for _, p := range exists {
		if p > first {
			out = append(out, fset.Position(p).String()+" is after the creating call at "+fset.Position(first).String())
		}
	}
	sort.Strings(out)
	return out
}
