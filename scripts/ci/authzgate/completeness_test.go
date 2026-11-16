package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// The trigger set matches references by name. That misses one call shape:
// a root reached through a function value whose name is unrelated (a struct
// field or variable assigned c.Authorize, or a parameter it is passed to,
// then called). This guard type-checks the tree, finds every reference to a
// root or permission constant (types.Info.Uses, so through any name, embedding
// or interface), follows function-value aliases (assignment, var
// initialiser, composite-literal field, call argument to a static callee's
// parameter, to a fixpoint), and fails for each reference inside a top-level
// declaration the trigger set does not hold. What it does not follow: values
// that flow through a return, a channel, a map/slice element or a closure
// capture; reflection.
func TestEveryRootReferenceIsInTheTriggerSet(t *testing.T) {
	g := guardrules.Rollout(t)
	m, _ := realModel(t)
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := loadTyped(t, root, nil, "./internal/...", "./server/...", "./pkg/...", "./cmd/...")
	misses, refs := uncoveredRootRefs(pkgs, m, root)
	t.Logf("%d typed references to roots and permission constants in the index", refs)
	if refs < 300 {
		g.Errorf("only %d root references found: the typed inventory is broken (roots renamed?)", refs)
	}
	for _, s := range misses {
		g.Errorf("not in the trigger set: %s", s)
	}
}

// Red and green for the guard itself, on a module that has both shapes.
func TestEveryRootReferenceIsInTheTriggerSet_Calibration(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("testdata", "aliasmod"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{"server/authzdiff/matrix.json": []byte(`{"rows":[{"core":"Gate"}]}`)}
	err = filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p) //nolint:gosec // testdata
		tr[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := newModel(tr)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := loadTyped(t, dir, []string{"GOWORK=off"}, "./...")
	misses, refs := uncoveredRootRefs(pkgs, m, dir)
	want := []string{
		"internal/core/core.go:15 checker.Gate references Authorize through check",
		"internal/core/core.go:19 viaParam references Authorize through f",
	}
	if !slices.Equal(misses, want) {
		t.Fatalf("misses (%d refs):\n%s\nwant:\n%s", refs, strings.Join(misses, "\n"), strings.Join(want, "\n"))
	}
}

func loadTyped(t *testing.T, dir string, env []string, patterns ...string) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:  dir,
		Env:  append(os.Environ(), env...),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatal(err)
	}
	var errs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		t.Fatalf("type-check errors (first 5): %s", strings.Join(errs[:min(5, len(errs))], "; "))
	}
	return pkgs
}

// uncoveredRootRefs returns "file:line decl references Root[ through alias]"
// for every typed reference to a root (or permission constant) inside an
// indexed declaration the model does not hold, and the number of references
// seen.
func uncoveredRootRefs(pkgs []*packages.Package, m *model, root string) (misses []string, refs int) {
	rel := func(p *packages.Package, id *ast.Ident) (string, int) {
		pos := p.Fset.Position(id.Pos())
		r, err := filepath.Rel(root, pos.Filename)
		if err != nil {
			return "", 0
		}
		return filepath.ToSlash(r), pos.Line
	}
	// declRel: the repository path of an object's declaration ("" outside).
	declRel := map[types.Object]string{}
	objFile := func(p *packages.Package, o types.Object) string {
		if s, ok := declRel[o]; ok {
			return s
		}
		s := ""
		if o.Pkg() != nil && o.Pos().IsValid() {
			if r, err := filepath.Rel(root, p.Fset.Position(o.Pos()).Filename); err == nil && !strings.HasPrefix(r, "..") {
				s = filepath.ToSlash(r)
			}
		}
		declRel[o] = s
		return s
	}
	isRoot := func(p *packages.Package, o types.Object) bool {
		switch o.(type) {
		case *types.Func, *types.Const, *types.Var:
		default:
			return false
		}
		f := objFile(p, o)
		if f == "" {
			return false
		}
		if _, isFunc := o.(*types.Func); isFunc && strings.HasPrefix(f, "server/") {
			return false // a handler named like a storage method is not a root (model.isRoot)
		}
		k := keyOf(filepath.ToSlash(filepath.Dir(f)), o.Name())
		if _, isConst := o.(*types.Const); isConst {
			return m.permDefs[k]
		}
		if v, isVar := o.(*types.Var); isVar {
			return !v.IsField() && m.roots[k] // adminRoleNames
		}
		return m.roots[k]
	}
	// aliasOf: function-valued vars/fields/params holding a root, and the root.
	aliasOf := map[types.Object]string{}
	valueRoot := func(p *packages.Package, e ast.Expr) string {
		e = ast.Unparen(e)
		var id *ast.Ident
		switch v := e.(type) {
		case *ast.Ident:
			id = v
		case *ast.SelectorExpr:
			id = v.Sel
		default:
			return ""
		}
		o := p.TypesInfo.Uses[id]
		if o == nil {
			return ""
		}
		if r, ok := aliasOf[o]; ok {
			return r
		}
		if _, isFunc := o.(*types.Func); isFunc && isRoot(p, o) {
			return o.Name()
		}
		return ""
	}
	objOfLHS := func(p *packages.Package, e ast.Expr) types.Object {
		e = ast.Unparen(e)
		var id *ast.Ident
		switch v := e.(type) {
		case *ast.Ident:
			id = v
		case *ast.SelectorExpr:
			id = v.Sel
		default:
			return nil
		}
		if o := p.TypesInfo.Defs[id]; o != nil {
			return o
		}
		return p.TypesInfo.Uses[id]
	}
	all := []*packages.Package{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo != nil {
			all = append(all, p)
		}
	})
	for changed := true; changed; {
		changed = false
		bind := func(o types.Object, r string) {
			if o == nil || r == "" {
				return
			}
			if _, done := aliasOf[o]; !done {
				aliasOf[o] = r
				changed = true
			}
		}
		for _, p := range all {
			for _, f := range p.Syntax {
				ast.Inspect(f, func(n ast.Node) bool {
					switch v := n.(type) {
					case *ast.AssignStmt:
						if len(v.Lhs) == len(v.Rhs) {
							for i := range v.Rhs {
								bind(objOfLHS(p, v.Lhs[i]), valueRoot(p, v.Rhs[i]))
							}
						}
					case *ast.ValueSpec:
						if len(v.Names) == len(v.Values) {
							for i := range v.Values {
								bind(p.TypesInfo.Defs[v.Names[i]], valueRoot(p, v.Values[i]))
							}
						}
					case *ast.KeyValueExpr:
						if k, ok := v.Key.(*ast.Ident); ok {
							bind(p.TypesInfo.Uses[k], valueRoot(p, v.Value))
						}
					case *ast.CallExpr:
						var fn *types.Func
						switch c := ast.Unparen(v.Fun).(type) {
						case *ast.Ident:
							fn, _ = p.TypesInfo.Uses[c].(*types.Func)
						case *ast.SelectorExpr:
							fn, _ = p.TypesInfo.Uses[c.Sel].(*types.Func)
						}
						if fn == nil {
							return true
						}
						sig, _ := fn.Type().(*types.Signature)
						if sig == nil {
							return true
						}
						for i, a := range v.Args {
							if i < sig.Params().Len() {
								bind(sig.Params().At(i).Origin(), valueRoot(p, a))
							}
						}
					}
					return true
				})
			}
		}
	}
	// Parameters are bound through their declaring signature's objects; the
	// function body uses the same *types.Var, so Uses below resolves them.
	seen := map[string]bool{}
	for _, p := range all {
		for id, o := range p.TypesInfo.Uses {
			r, alias := aliasOf[o]
			if !alias && !isRoot(p, o) {
				continue
			}
			file, line := rel(p, id)
			if file == "" || !inScope(file) {
				continue
			}
			refs++
			var d *decl
			for _, x := range m.ix.byFile[file] {
				if line >= x.start && line <= x.end {
					d = x
					break
				}
			}
			what := o.Name()
			if alias {
				what = r + " through " + o.Name()
			}
			var s string
			switch {
			case d == nil:
				s = fmt.Sprintf("%s:%d (no top-level declaration) references %s", file, line, what)
			case m.reason(d) == "":
				s = fmt.Sprintf("%s:%d %s references %s", file, line, qual(d), what)
			default:
				continue
			}
			if !seen[s] {
				seen[s] = true
				misses = append(misses, s)
			}
		}
	}
	slices.Sort(misses)
	return misses, refs
}
