// named_lock_overlap_inventory_test.go — NAMEDLOCK-OVERLAP-1: every
// WithNamedLock call site in the core family has a row in the inventory table of
// docs/design/named-lock-overlap.md, which records what the section protects and
// whether losing the lock mid-section (the POOLER-LOCKLOSS-1 overlap window) can
// break it. A new call site fails here until someone writes that row; a row whose
// call site is gone fails too, so the table cannot drift into fiction.
//
// A call site is (repo-relative file, enclosing function, key expression as
// printed by go/types.ExprString). Recognised call shape: a selector call named
// WithNamedLock with three arguments, any receiver (c.storage, ls, a tx handle),
// the same shape named_lock_order_static_test.go counts. What this does not see:
// a lock taken through a method value or a func variable (none exist; a
// WithNamedLock reached that way would also escape the lock-order guard), and
// whether the verdict written in the row is right: that stays a review question.
package guards

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const namedLockOverlapDoc = "docs/design/named-lock-overlap.md"

type namedLockSite struct{ file, fn, key string }

func (s namedLockSite) String() string { return fmt.Sprintf("%s | %s | %s", s.file, s.fn, s.key) }

func TestNamedLockOverlap_EveryCallSiteIsInventoried(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()

	code := map[namedLockSite]token.Position{}
	fset := token.NewFileSet()
	for _, p := range coreFamilySources(t) {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range namedLockSitesIn(f, filepath.ToSlash(rel), fset) {
			code[s.site] = s.pos
		}
	}
	if len(code) < 30 {
		t.Fatalf("found only %d WithNamedLock call sites in the core family: the scan stopped seeing them", len(code))
	}

	rows, err := readNamedLockInventory(filepath.Join(root, namedLockOverlapDoc))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sortedSites(code) {
		if !rows[s] {
			g.Errorf("%s: WithNamedLock call site (%s) has no row in %s: add one saying what the section protects and whether the lock-loss overlap can break it", code[s], s, namedLockOverlapDoc)
		}
	}
	var stale []namedLockSite
	for s := range rows {
		if _, ok := code[s]; !ok {
			stale = append(stale, s)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].String() < stale[j].String() })
	for _, s := range stale {
		g.Errorf("%s names a WithNamedLock call site that no longer exists (%s): update or delete the row", namedLockOverlapDoc, s)
	}
}

type positionedSite struct {
	site namedLockSite
	pos  token.Position
}

// namedLockSitesIn returns every WithNamedLock(ctx, key, fn) call in f, keyed by
// its enclosing top-level function (a closure counts as its enclosing func).
func namedLockSitesIn(f *ast.File, rel string, fset *token.FileSet) []positionedSite {
	var out []positionedSite
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WithNamedLock" || len(ce.Args) != 3 {
				return true
			}
			out = append(out, positionedSite{
				site: namedLockSite{file: rel, fn: fd.Name.Name, key: types.ExprString(ce.Args[1])},
				pos:  fset.Position(ce.Pos()),
			})
			return true
		})
	}
	return out
}

// readNamedLockInventory returns the (file, function, key) of every table row
// whose first cell is a .go path. Cells may be wrapped in backticks.
func readNamedLockInventory(path string) (map[namedLockSite]bool, error) {
	f, err := os.Open(path) // #nosec G304 -- fixed repository path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rows := map[namedLockSite]bool{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(text, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(text, "|"), "|")
		if len(cells) < 3 {
			continue
		}
		cell := func(i int) string { return strings.Trim(strings.TrimSpace(cells[i]), "`") }
		if !strings.HasSuffix(cell(0), ".go") {
			continue
		}
		s := namedLockSite{file: cell(0), fn: cell(1), key: cell(2)}
		if rows[s] {
			return nil, fmt.Errorf("%s:%d: duplicate row %s", path, line, s)
		}
		rows[s] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: no inventory rows found (table format changed?)", path)
	}
	return rows, nil
}

func sortedSites(m map[namedLockSite]token.Position) []namedLockSite {
	out := make([]namedLockSite, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
