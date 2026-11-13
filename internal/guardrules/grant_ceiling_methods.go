package guardrules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// grantCeilingFuncs are internal/core's grant-ceiling checks: the functions whose
// refusal (core.ErrPermissionDenied) says "the actor may not grant this". Every
// exported KeyorixCore method that reaches one of them, directly or through one
// unexported method of the same type, is a granting method, and every transport
// call of a granting method must map the refusal to 403 / PermissionDenied
// (TestEveryGrantingServiceMapsPermissionDenied; the REST twin lands with #4165 as
// TestEveryGrantingHandlerMapsTheCeilingRefusal).
var grantCeilingFuncs = map[string]bool{
	"requireGranterHoldsRolePermissions":      true,
	"requireGranterHoldsRoleSet":              true,
	"requireAuthorityForRole":                 true,
	"requireMachinePrivilegeCeiling":          true,
	"requireAuthorityToReinstateProjectRoles": true,
	"requireBaselineRoleGrantAuthority":       true,
}

// GrantCeilingMethods derives, from the non-test Go files of coreDir
// (internal/core), the exported *KeyorixCore methods that enforce a grant ceiling:
// a method whose body calls one of the ceiling functions, or calls an unexported
// KeyorixCore method that does (one hop; the hop is followed through `c.m(...)` on
// the receiver only). The result is sorted. It over-approximates by name: a method
// that reaches a ceiling check only on some path is listed, which is harmless (its
// caller then maps a refusal it may never see). It does not follow function values,
// closures assigned to variables, or calls through another type.
func GrantCeilingMethods(coreDir string) ([]string, error) {
	entries, err := os.ReadDir(coreDir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	type method struct {
		exported bool
		calls    map[string]bool // methods called on the receiver, and bare function calls
	}
	methods := map[string]*method{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(coreDir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			if recvType(fd.Recv.List[0].Type) != "KeyorixCore" {
				continue
			}
			recvName := ""
			if len(fd.Recv.List[0].Names) == 1 {
				recvName = fd.Recv.List[0].Names[0].Name
			}
			m := &method{exported: ast.IsExported(fd.Name.Name), calls: map[string]bool{}}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					m.calls[fn.Name] = true
				case *ast.SelectorExpr:
					if id, ok := fn.X.(*ast.Ident); ok && recvName != "" && id.Name == recvName {
						m.calls[fn.Sel.Name] = true
					}
				}
				return true
			})
			methods[fd.Name.Name] = m
		}
	}
	reaches := func(m *method) bool {
		for c := range m.calls {
			if grantCeilingFuncs[c] {
				return true
			}
		}
		return false
	}
	var out []string
	for name, m := range methods {
		if !m.exported {
			continue
		}
		hit := reaches(m)
		for c := range m.calls {
			if hit {
				break
			}
			if inner, ok := methods[c]; ok && !inner.exported && reaches(inner) {
				hit = true
			}
		}
		if hit {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func recvType(t ast.Expr) string {
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
