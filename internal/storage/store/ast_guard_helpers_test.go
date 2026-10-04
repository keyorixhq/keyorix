// ast_guard_helpers_test.go — syntactic helpers shared by the C-GUARD-3 AST
// guards in this package (full_row_write_guard_test.go,
// parent_liveness_registry_test.go). No type checker: model types are resolved
// from the enclosing function's parameters and local declarations only, and
// anything else is reported as "?" so a guard can fail closed on it.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fullRowArgModel resolves the model type name of a Save/Updates argument.
// "" means "not a models.* type" (not a hit); "?" means "could not resolve".
func fullRowArgModel(fd *ast.FuncDecl, arg ast.Expr) string {
	if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
		arg = u.X
	}
	switch a := arg.(type) {
	case *ast.CompositeLit:
		return modelsTypeName(a.Type)
	case *ast.Ident:
		return resolveIdentModel(fd, a.Name)
	case *ast.CallExpr:
		if id, ok := a.Fun.(*ast.Ident); ok && id.Name == "new" && len(a.Args) == 1 {
			return modelsTypeName(a.Args[0])
		}
	case *ast.IndexExpr, *ast.SelectorExpr:
		return "?"
	}
	return "?"
}

// modelsTypeName returns T for `models.T`, `*models.T`, `[]models.T`,
// `[]*models.T`; "" for anything else.
func modelsTypeName(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.StarExpr:
			e = v.X
			continue
		case *ast.ArrayType:
			e = v.Elt
			continue
		case *ast.SelectorExpr:
			if id, ok := v.X.(*ast.Ident); ok && id.Name == "models" {
				return v.Sel.Name
			}
		}
		return ""
	}
}

func resolveIdentModel(fd *ast.FuncDecl, name string) string {
	if fd.Type.Params != nil {
		for _, p := range fd.Type.Params.List {
			for _, n := range p.Names {
				if n.Name == name {
					if m := modelsTypeName(p.Type); m != "" {
						return m
					}
					return ""
				}
			}
		}
	}
	found := "?"
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			for _, id := range v.Names {
				if id.Name == name && v.Type != nil {
					found = modelsTypeName(v.Type)
				}
			}
		case *ast.AssignStmt:
			if v.Tok != token.DEFINE {
				return true
			}
			for i, l := range v.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name != name || i >= len(v.Rhs) {
					continue
				}
				r := v.Rhs[i]
				if u, ok := r.(*ast.UnaryExpr); ok && u.Op == token.AND {
					r = u.X
				}
				switch rv := r.(type) {
				case *ast.CompositeLit:
					found = modelsTypeName(rv.Type)
				case *ast.CallExpr:
					if fid, ok := rv.Fun.(*ast.Ident); ok && fid.Name == "new" && len(rv.Args) == 1 {
						found = modelsTypeName(rv.Args[0])
					}
				}
			}
		}
		return true
	})
	return found
}

func funcDisplayName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	x := fd.Recv.List[0].Type
	ptr := false
	if st, ok := x.(*ast.StarExpr); ok {
		x, ptr = st.X, true
	}
	name := "?"
	if id, ok := x.(*ast.Ident); ok {
		name = id.Name
	}
	if ptr {
		return "(*" + name + ")." + fd.Name.Name
	}
	return name + "." + fd.Name.Name
}

func parseNonTestGoFiles(t *testing.T, dir string) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no non-test Go files under %s — the guard's scan root moved; update it", dir)
	}
	return fset, files
}
