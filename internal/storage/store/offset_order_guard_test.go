package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Class guard for INV-STORE-paged-lists-total-order: a query paged with
// .Offset(...) must also be ordered by a unique final key, otherwise the rows of
// page N depend on the query plan and a page walk repeats and skips rows.
//
// What it recognises: a call of the form <expr>.Offset(...) in a non-test Go file
// of internal/storage/store or internal/encryption. The enclosing function must
// contain an <expr>.Order("<literal>") call whose last comma-separated sort key is
// the id column ("id", "t.id", optionally followed by ASC/DESC). The Order call may
// sit on a different statement than the Offset (the audit list builds the query in
// steps), so the check is per function, not per call chain.
//
// What it does not do: it cannot tell that the id Order is applied to the same
// query value as the Offset, it does not follow a query passed to another function,
// and it does not recognise Order built from a non-literal or a Limit-only list
// (those are not offset-paged). A function that pages with a keyset (id > last)
// has no .Offset( call and is out of scope.
func offsetWithoutIDTiebreak(t *testing.T, filename string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	require.NoError(t, err)
	var bad []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var offsets []token.Pos
		hasIDOrder := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Offset":
				offsets = append(offsets, call.Pos())
			case "Order":
				if len(call.Args) == 1 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil && lastSortKeyIsID(v) {
							hasIDOrder = true
						}
					}
				}
			}
			return true
		})
		if len(offsets) > 0 && !hasIDOrder {
			for _, p := range offsets {
				bad = append(bad, fset.Position(p).String()+" in "+fn.Name.Name)
			}
		}
	}
	return bad
}

func lastSortKeyIsID(order string) bool {
	keys := strings.Split(order, ",")
	fields := strings.Fields(keys[len(keys)-1])
	if len(fields) == 0 || len(fields) > 2 {
		return false
	}
	if len(fields) == 2 {
		if dir := strings.ToUpper(fields[1]); dir != "ASC" && dir != "DESC" {
			return false
		}
	}
	col := fields[0]
	if i := strings.LastIndex(col, "."); i >= 0 {
		col = col[i+1:]
	}
	return col == "id"
}

func TestOffsetPagedQueriesEndInUniqueIDOrder(t *testing.T) {
	var checked int
	for _, dir := range []string{".", filepath.Join("..", "..", "encryption")} {
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path) // #nosec G304 -- fixed in-repo directories
			require.NoError(t, err)
			if !strings.Contains(string(data), ".Offset(") {
				continue
			}
			checked++
			require.Empty(t, offsetWithoutIDTiebreak(t, path, data),
				"%s: an offset-paged query needs an Order whose last key is the unique id (INV-STORE-paged-lists-total-order)", path)
		}
	}
	// The scan must have seen the known offset-paged files, or it is vacuous.
	require.GreaterOrEqual(t, checked, 4, "expected local_users.go, local_secrets.go, local_audit_list.go and sweep.go")
}

// Calibration: the checker goes red on an unordered or non-unique-ordered Offset
// and stays green on the shapes the repo uses.
func TestOffsetPagedQueriesGuard_Calibration(t *testing.T) {
	const head = "package p\nfunc f(q Q) {\n"
	cases := []struct {
		name string
		body string
		bad  bool
	}{
		{"no order", `q.Offset(1).Limit(2)`, true},
		{"order by non-unique key", `q.Order("name").Offset(1)`, true},
		{"order by id then name", `q.Order("id, name").Offset(1)`, true},
		{"non-literal order", `q.Order(k).Offset(1)`, true},
		{"id", `q.Order("id").Offset(1)`, false},
		{"qualified id asc", `q.Order("users.id ASC").Offset(1)`, false},
		{"key then id", `q.Order("name ASC, id ASC").Offset(1)`, false},
		{"order on another statement", "q = q.Offset(1)\nq.Order(\"event_time DESC, id DESC\")", false},
		{"no offset", `q.Order("name").Limit(1)`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := offsetWithoutIDTiebreak(t, "x.go", head+c.body+"\n}\n")
			if c.bad {
				require.NotEmpty(t, got)
			} else {
				require.Empty(t, got)
			}
		})
	}
}
