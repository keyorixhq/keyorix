package corshostile

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/cors"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// routerDir is server/http, whose router.go builds the live cors.Options.
var routerDir = filepath.Join("..", "..", "..", "server", "http")

// readRouterSources returns the non-test .go files of server/http by name.
func readRouterSources(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(routerDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string][]byte{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		srcs[filepath.Base(p)] = b
	}
	if _, ok := srcs["router.go"]; !ok {
		t.Fatalf("server/http/router.go not found under %s", routerDir)
	}
	return srcs
}

// routerCORSOptions evaluates the single `cors.Options{...}` literal in the
// given server/http sources, with AllowedOrigins left nil (router.go computes it
// at runtime from config). String elements may be literals or package-level
// string constants. Any field or expression shape it does not know fails the
// test, so a new option in router.go cannot slip past the mirror unseen.
func routerCORSOptions(t *testing.T, srcs map[string][]byte) cors.Options {
	t.Helper()
	fset := token.NewFileSet()
	consts := map[string]string{}
	var lits []*ast.CompositeLit
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						v, err := strconv.Unquote(bl.Value)
						if err == nil {
							consts[id.Name] = v
						}
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if sel, ok := cl.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Options" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "cors" {
					lits = append(lits, cl)
				}
			}
			return true
		})
	}
	if len(lits) != 1 {
		t.Fatalf("found %d cors.Options literals in server/http, want exactly 1", len(lits))
	}

	str := func(e ast.Expr) string {
		switch x := e.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if v, err := strconv.Unquote(x.Value); err == nil {
					return v
				}
			}
		case *ast.Ident:
			if v, ok := consts[x.Name]; ok {
				return v
			}
		}
		t.Fatalf("cors.Options element %T at %s is not a string literal or known constant; extend routerCORSOptions", e, fset.Position(e.Pos()))
		return ""
	}
	strs := func(e ast.Expr) []string {
		cl, ok := e.(*ast.CompositeLit)
		if !ok {
			t.Fatalf("cors.Options list at %s is not a []string literal", fset.Position(e.Pos()))
		}
		out := make([]string, 0, len(cl.Elts))
		for _, el := range cl.Elts {
			out = append(out, str(el))
		}
		return out
	}

	var got cors.Options
	for _, el := range lits[0].Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			t.Fatalf("cors.Options literal uses positional fields")
		}
		key := kv.Key.(*ast.Ident).Name
		switch key {
		case "AllowedOrigins":
			// Runtime value (getAllowedOrigins); the harness supplies its own lists.
		case "AllowedMethods":
			got.AllowedMethods = strs(kv.Value)
		case "AllowedHeaders":
			got.AllowedHeaders = strs(kv.Value)
		case "ExposedHeaders":
			got.ExposedHeaders = strs(kv.Value)
		case "MaxAge":
			bl, ok := kv.Value.(*ast.BasicLit)
			if !ok || bl.Kind != token.INT {
				t.Fatalf("MaxAge is not an int literal")
			}
			v, err := strconv.Atoi(bl.Value)
			if err != nil {
				t.Fatal(err)
			}
			got.MaxAge = v
		case "AllowCredentials":
			id, ok := kv.Value.(*ast.Ident)
			if !ok || (id.Name != "true" && id.Name != "false") {
				t.Fatalf("AllowCredentials is not a bool literal")
			}
			got.AllowCredentials = id.Name == "true"
		default:
			t.Fatalf("router.go sets cors.Options.%s, which keyorixCORSOptions and this test do not mirror: update both", key)
		}
	}
	return got
}

// TestCORSOptions_MirrorRouter guards INV-FUZZCORS-options-mirror-router: the
// harness's keyorixCORSOptions must equal router.go's live option set (all but
// AllowedOrigins), so the oracles test the configuration Keyorix really runs.
func TestCORSOptions_MirrorRouter(t *testing.T) {
	got := routerCORSOptions(t, readRouterSources(t))
	if want := keyorixCORSOptions(nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("keyorixCORSOptions drifted from server/http/router.go:\n router.go: %+v\n mirror:    %+v", got, want)
	}
}

// TestCORSOptions_MirrorRouter_RedGreen proves the mirror check can fail: a
// router.go with one more allowed method no longer equals the mirror.
func TestCORSOptions_MirrorRouter_RedGreen(t *testing.T) {
	srcs := readRouterSources(t)
	const from = `"OPTIONS", "PATCH"}`
	if !bytes.Contains(srcs["router.go"], []byte(from)) {
		t.Skipf("router.go no longer contains %s; update this red/green probe", from)
	}
	srcs["router.go"] = bytes.Replace(srcs["router.go"], []byte(from), []byte(`"OPTIONS", "PATCH", "TRACE"}`), 1)
	if got := routerCORSOptions(t, srcs); reflect.DeepEqual(got, keyorixCORSOptions(nil)) {
		t.Fatal("mirror check stayed green after router.go gained an allowed method")
	}
}

// TestCORSBudget_LiveHeapNotMetered guards INV-FUZZCORS-liveheap-not-metered:
// the committed budget meters the input-attributable alloc_bytes and mallocs
// and leaves out the whole-process live_heap reading.
func TestCORSBudget_LiveHeapNotMetered(t *testing.T) {
	b, err := resguard.LoadBudget("testdata/resguard-cors.json")
	if err != nil {
		t.Fatalf("committed budget: %v", err)
	}
	for _, m := range []string{"alloc_bytes", "mallocs"} {
		if _, ok := b.Meters[m]; !ok {
			t.Errorf("budget has no %s ceiling; meters=%v", m, b.Summary())
		}
	}
	if _, ok := b.Meters["live_heap"]; ok {
		t.Errorf("budget meters live_heap, which is dominated by the fuzz engine's own heap; meters=%v", b.Summary())
	}
}
