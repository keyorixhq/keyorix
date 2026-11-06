package authzdiff

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGlobalHandlerFlagMatchesRouter: an op whose REST route is served by a
// package-level handler that delegates to handlers.defaultUserHandler (the
// /users routes, the MFA-reset routes) must set globalHandler. Without it the
// REST leg would run against whichever leg's core last re-pointed that global:
// a wrong outcome, not a crash.
//
// The delegating functions are derived from the handlers package source (a
// top-level func whose body names defaultUserHandler); the route -> handler
// mapping is matrix.json's. An op whose route is not in matrix.json is not
// checked here (TestMatrixKeysAreCurrent covers matrix freshness).
func TestGlobalHandlerFlagMatchesRouter(t *testing.T) {
	delegating := defaultUserHandlerFuncs(t)
	if len(delegating) == 0 {
		t.Fatal("no handlers func references defaultUserHandler: the derivation is broken")
	}
	b, err := os.ReadFile("matrix.json")
	if err != nil {
		t.Fatalf("matrix.json: %v", err)
	}
	var m struct {
		Ops []struct {
			Key     string `json:"key"`
			Layer   string `json:"layer"`
			Handler string `json:"handler"`
		} `json:"ops"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("matrix.json: %v", err)
	}
	handlerOf := map[string]string{}
	for _, op := range m.Ops {
		if op.Layer == "rest" {
			handlerOf[strings.TrimPrefix(op.Key, "REST ")] = op.Handler
		}
	}
	_, fx := template(t)
	checked := 0
	for _, spec := range ops() {
		if spec.rest == nil {
			continue
		}
		route := opRouteKey(t, fx, spec)
		fn, ok := strings.CutPrefix(handlerOf[route], "handlers.")
		if !ok || !delegating[fn] {
			continue
		}
		checked++
		if !spec.globalHandler {
			t.Errorf("op %s: route %s is served by handlers.%s, which delegates to defaultUserHandler; set globalHandler", spec.name, route, fn)
		}
	}
	if checked == 0 {
		t.Fatal("no op is served through defaultUserHandler: the check is vacuous")
	}
}

func defaultUserHandlerFuncs(tb testing.TB) map[string]bool {
	tb.Helper()
	files, err := filepath.Glob(filepath.Join("..", "http", "handlers", "*.go"))
	if err != nil {
		tb.Fatal(err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			tb.Fatalf("%s: %v", f, err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == "defaultUserHandler" {
					out[fd.Name.Name] = true
					return false
				}
				return true
			})
		}
	}
	return out
}
