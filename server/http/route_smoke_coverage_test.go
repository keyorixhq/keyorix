package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestEveryRouteHasAnE2ESmokeCallOrSkip is the static half of scripts/e2e's
// assertRouteCoverage, the check TestAPISmoke_SQLite runs at the end of its walk:
// every route router.go registers must be called by the smoke driver or listed in
// its skipList with a reason. The smoke runs only in the merge queue (FULL
// profile), so a PR that adds a route without either first failed there, after
// a 30-minute round (runs 38027075446 on 10 Oct; 40104602650, 40105497523 and
// 40106284117 for one PR on 24 Oct). This test runs wherever server/http's tests
// run, including a pull request's quick tier, and names the route.
//
// It reads the driver's sources instead of running it: a route counts as called
// when some call in scripts/e2e/*.go passes its "METHOD /pattern" key as a string
// literal argument (c.call, c.callExpect, c.doRaw, c.skip and their wrappers) or
// builds it with the driver's one loop idiom (e2eLoopBuiltRouteKeys), and as
// skipped when it is a key of coverage.go's skipList.
//
// What it does NOT cover: a call the driver makes only on a branch that does not
// run (the dynamic check still catches that), a key built at run time any other
// way (its route reads as missing, a false red), a key literal passed to a call
// that is not a smoke call (it reads as called), and the route_user_path_ratchet's
// journey/web-spec references.
func TestEveryRouteHasAnE2ESmokeCallOrSkip(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	routes := buildRouteInventory(t, filepath.Join(root, "server", "http", "router.go"))
	if len(routes) == 0 {
		t.Fatal("found 0 routes in NewRouter: the inventory walk is vacuous")
	}
	e2eDir := filepath.Join(root, "scripts", "e2e")
	called := e2eSmokeCalledRouteKeys(t, e2eDir)
	skipped := e2eSmokeSkipListKeys(t, filepath.Join(e2eDir, "coverage.go"))
	if len(called) < 100 || len(skipped) < 10 {
		t.Fatalf("found %d called and %d skipped route keys in %s: the source scan is broken, fix it, not this floor", len(called), len(skipped), e2eDir)
	}

	var missing []string
	known := map[string]bool{}
	for _, r := range routes {
		k := r.Method + " " + r.Pattern
		known[k] = true
		if !called[k] && !skipped[k] {
			missing = append(missing, k)
		}
	}
	var stale []string
	for k := range skipped {
		if !known[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("%d route(s) are neither called by the e2e smoke driver nor in its skipList; TestAPISmoke_SQLite will fail "+
			"in the merge queue. Add a c.callExpect(...) to a scripts/e2e/groups_*.go group, or a skipList entry with the reason "+
			"(scripts/e2e/coverage.go):\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d skipList entr(y/ies) in scripts/e2e/coverage.go match no route in router.go (moved or removed); "+
			"TestAPISmoke_SQLite will fail on them:\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
}

var e2eRouteKeyRx = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /\S*$`)

// e2eSmokeCalledRouteKeys returns every "METHOD /pattern" string literal passed as
// an argument to a call anywhere in dir's .go files (all build tags: the driver is
// //go:build e2e).
func e2eSmokeCalledRouteKeys(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no .go files in %s: %v", dir, err)
	}
	keys := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, a := range call.Args {
				if s, ok := e2eStringLit(a); ok && e2eRouteKeyRx.MatchString(s) {
					keys[s] = true
				}
			}
			return true
		})
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				for _, k := range e2eLoopBuiltRouteKeys(fn.Body) {
					keys[k] = true
				}
			}
		}
	}
	return keys
}

// e2eLoopBuiltRouteKeys expands the one loop idiom the driver uses for its read-only
// sweeps (groupCompliance, the per-project and per-secret GETs):
//
//	segs := []string{"a", "b"}
//	for _, seg := range segs { c.call("GET", fmt.Sprintf("GET /x/%s", seg), ...) }
//
// The range expression may also be the []string literal itself. Any other way of
// building a key at run time is not recognised, and its routes read as missing.
func e2eLoopBuiltRouteKeys(body *ast.BlockStmt) []string {
	lists := map[string][]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				if elems, ok := e2eStringSliceLit(as.Rhs[0]); ok {
					lists[id.Name] = elems
				}
			}
		}
		return true
	})
	var keys []string
	ast.Inspect(body, func(n ast.Node) bool {
		rs, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		v, ok := rs.Value.(*ast.Ident)
		if !ok {
			return true
		}
		elems, ok := e2eStringSliceLit(rs.X)
		if id, isID := rs.X.(*ast.Ident); !ok && isID {
			elems, ok = lists[id.Name]
		}
		if !ok {
			return true
		}
		ast.Inspect(rs.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Sprintf" {
				return true
			}
			format, ok := e2eStringLit(call.Args[0])
			arg, isID := call.Args[1].(*ast.Ident)
			if !ok || !isID || arg.Name != v.Name || strings.Count(format, "%s") != 1 || strings.Count(format, "%") != 1 {
				return true
			}
			for _, e := range elems {
				if k := strings.Replace(format, "%s", e, 1); e2eRouteKeyRx.MatchString(k) {
					keys = append(keys, k)
				}
			}
			return true
		})
		return true
	})
	return keys
}

func e2eStringSliceLit(e ast.Expr) ([]string, bool) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	arr, ok := lit.Type.(*ast.ArrayType)
	if !ok {
		return nil, false
	}
	if id, ok := arr.Elt.(*ast.Ident); !ok || id.Name != "string" {
		return nil, false
	}
	out := make([]string, 0, len(lit.Elts))
	for _, el := range lit.Elts {
		s, ok := e2eStringLit(el)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// e2eSmokeSkipListKeys returns the keys of the skipList map literal in coverage.go.
func e2eSmokeSkipListKeys(t *testing.T, path string) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	keys := map[string]bool{}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "skipList" || len(vs.Values) != 1 {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		found = true
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if s, ok := e2eStringLit(kv.Key); ok {
					keys[s] = true
				}
			}
		}
		return false
	})
	if !found {
		t.Fatalf("no `skipList = map[string]string{...}` literal in %s: the scan is out of date", path)
	}
	return keys
}

func e2eStringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}
