package services

// grant_refusal_mapping_guard_test.go — FIX-ERRMAP-STRUCT-1 item 4 (#3979, #4020): every
// gRPC service method that calls a GRANTING core method (one that enforces a grant
// ceiling, derived by guardrules.GrantCeilingMethods from internal/core, the same set
// the REST guard server/http/handlers/grant_refusal_mapping_guard_test.go uses) hands
// the error to a mapper that classifies core.ErrPermissionDenied (PermissionDenied,
// never Internal): the shared adapter coreErrorStatus, or a same-package function
// whose body evaluates errors.Is(_, core.ErrPermissionDenied).
//
// What it recognises: a method whose body calls `s.core.M(...)` with M in the derived
// set; mapped when the body calls coreErrorStatus or a same-package function/method
// whose body does, or whose body mentions core.ErrPermissionDenied (one hop). Not
// followed: two hops, function values, mappers in another package.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// grantRefusalStatusExempt names services ("file.go:Func") that call a granting method
// without mapping the refusal, each for a stated reason.
var grantRefusalStatusExempt = map[string]string{}

func mentionsPermissionDenied(fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "ErrPermissionDenied" {
				found = true
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "coreErrorStatus" {
				found = true
			}
		}
		return !found
	})
	return found
}

// grantRefusalStatusViolations returns each "file:func -> M" of dir whose method calls
// a granting method M on s.core without routing the error through a mapper that
// classifies ErrPermissionDenied, and how many granting calls it saw.
func grantRefusalStatusViolations(t *testing.T, dir string, granting map[string]bool, exempt map[string]string) (violations []string, seen int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	type parsed struct {
		name string
		file *ast.File
	}
	var files []parsed
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, parsed{name, f})
	}
	// Mappers: package-level functions and methods whose body classifies the sentinel.
	mappers := map[string]bool{}
	for _, pf := range files {
		for _, d := range pf.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && mentionsPermissionDenied(fd) {
				mappers[fd.Name.Name] = true
			}
		}
	}
	for _, pf := range files {
		for _, d := range pf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			var calls []string
			mapped := mentionsPermissionDenied(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if mappers[fn.Name] {
						mapped = true
					}
				case *ast.SelectorExpr:
					if recv, ok := fn.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "core" && granting[fn.Sel.Name] {
						calls = append(calls, fn.Sel.Name)
					} else if mappers[fn.Sel.Name] {
						mapped = true
					}
				}
				return true
			})
			seen += len(calls)
			if len(calls) == 0 || mapped {
				continue
			}
			if _, ok := exempt[pf.name+":"+fd.Name.Name]; ok {
				continue
			}
			violations = append(violations, pf.name+":"+fd.Name.Name+" -> "+strings.Join(calls, ","))
		}
	}
	slices.Sort(violations)
	return violations, seen
}

// TestEveryGrantingServiceMapsPermissionDenied reports through guardrules.Rollout
// (report-only on pull requests while its docs/guard-rollout.d row exists).
func TestEveryGrantingServiceMapsPermissionDenied(t *testing.T) {
	g := guardrules.Rollout(t)
	names, err := guardrules.GrantCeilingMethods(filepath.Join("..", "..", "..", "internal", "core"))
	if err != nil {
		t.Fatal(err)
	}
	granting := map[string]bool{}
	for _, n := range names {
		granting[n] = true
	}
	violations, seen := grantRefusalStatusViolations(t, ".", granting, grantRefusalStatusExempt)
	if seen < 4 {
		t.Fatalf("saw only %d s.core calls of a granting method: the scan is broken", seen)
	}
	if len(violations) > 0 {
		g.Errorf("these gRPC methods call a granting core method without a mapper that classifies "+
			"core.ErrPermissionDenied (a grant-ceiling refusal would be Internal): route the error through "+
			"coreErrorStatus, or add a reasoned exemption to grantRefusalStatusExempt:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestGrantRefusalStatusGuardCalibration(t *testing.T) {
	dir := t.TempDir()
	src := `package services
func (s *S) Bad(ctx C, req R) error      { if err := s.core.AssignUserRole(); err != nil { return status.Error(codes.Internal, "x") }; return nil }
func (s *S) Adapter(ctx C, req R) error  { if err := s.core.AssignUserRole(); err != nil { return coreErrorStatus(ctx, err, coreErrorStatusOpts{}) }; return nil }
func (s *S) Mapper(ctx C, req R) error   { if err := s.core.AssignUserRole(); err != nil { return mapRoleError(err) }; return nil }
func (s *S) Plain(ctx C, req R) error    { if err := s.core.AssignUserRole(); err != nil { return mapPlain(err) }; return nil }
func (s *S) NotGranting(ctx C, req R) error { if err := s.core.GetProject(); err != nil { return mapPlain(err) }; return nil }
func mapRoleError(err error) error { if errors.Is(err, core.ErrPermissionDenied) { return nil }; return err }
func mapPlain(err error) error { return err }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen := grantRefusalStatusViolations(t, dir, map[string]bool{"AssignUserRole": true}, nil)
	want := []string{"synthetic.go:Bad -> AssignUserRole", "synthetic.go:Plain -> AssignUserRole"}
	if seen != 4 || !slices.Equal(violations, want) {
		t.Fatalf("calibration: seen=%d violations=%v, want 4 and exactly %v", seen, violations, want)
	}
}
