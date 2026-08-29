// role_rename_unreachable_guard_test.go — #1494's closure rests on role
// renaming being structurally unreachable, not on IsBuiltinRole being
// correct: UpdateRoleRequest carries no field mapping to models.Role.Name on
// either transport, so there is no rename call site for IsBuiltinRole (or
// anything else) to guard. That precondition is the property this test
// asserts. A guard aimed at the conclusion instead ("every rename path
// passes through IsBuiltinRole") would be checking a population of exactly
// zero call sites and would pass unconditionally, forever, regardless of
// whether IsBuiltinRole is wired correctly, deleted, or never called at all
// -- the same failure shape as `git merge-base --is-ancestor <branch>
// origin/main` across a squash-merge boundary, which returns false for
// every correctly landed PR and so proves nothing by passing OR failing.
//
// AST over the two struct definitions, not a string grep: a grep for
// `"Name"` as text would miss a field added under a different Go identifier
// that still serializes as "name" on the wire (or vice versa), and would
// need updating by hand if the struct itself is renamed or moved. Parsing
// the actual type declaration is what makes this fire on the field itself
// appearing, not on incidental nearby text changes.
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// roleUpdateRequestSources names, for each transport, the file containing
// UpdateRoleRequest's field definitions. Both are real, compiled Go types --
// server/proto/pb/keyorix.pb.go is generated, but it's the actual struct
// server/grpc/services/role_service.go decodes into, not the .proto IDL, so
// it's the correct source of truth to parse.
var roleUpdateRequestSources = []struct {
	transport string
	path      string
}{
	{"HTTP", filepath.Join("handlers", "rbac.go")},
	{"gRPC", filepath.Join("..", "proto", "pb", "keyorix.pb.go")},
}

// roleNameFieldName is the field name that would map to models.Role.Name if
// renaming were ever wired up -- "Name", matching how every other field
// already on UpdateRoleRequest names itself after the model field it sets
// (Description → Role.Description, Permissions → the role's permission
// set). This is deliberately narrow: the assertion is "no field maps to
// Role.Name specifically," not "no new field of any kind" -- a guard that
// fired on an unrelated addition would get weakened to make the build pass,
// and a weakened guard is worse than none.
const roleNameFieldName = "Name"

// TestUpdateRoleRequest_CarriesNoNameField is #1494's structural-
// unreachability guard: it fails the moment either transport's
// UpdateRoleRequest gains a direct field named "Name" -- the day someone
// adds one, this fires and the IsBuiltinRole-coverage question has to be
// re-asked before the field ships, not after a finding reopens #1494. Only
// DIRECT fields are checked (field.Names, not promoted fields from an
// embedded type) -- neither current struct embeds anything, and widening to
// walk embedded types isn't needed until one does.
//
// If UpdateRoleRequest can no longer be found as a literal struct type in
// its source file (renamed, restructured, or turned into a type alias for
// another type), this fails loudly rather than silently reporting "no Name
// field found" -- a type alias or a moved definition means this guard can
// no longer verify anything and needs a human to update it, not a pass it
// didn't earn.
func TestUpdateRoleRequest_CarriesNoNameField(t *testing.T) {
	for _, src := range roleUpdateRequestSources {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, src.path, nil, 0)
		if err != nil {
			t.Fatalf("%s: parsing %s: %v", src.transport, src.path, err)
		}

		st, found := findStructType(f, "UpdateRoleRequest")
		if !found {
			t.Fatalf("%s: UpdateRoleRequest struct not found (as a literal struct type) in %s -- this guard "+
				"can no longer verify #1494's closure and needs updating alongside whatever moved, renamed, "+
				"or aliased the type, not silently skipped", src.transport, src.path)
		}

		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				if name.Name == roleNameFieldName {
					t.Errorf("%s: UpdateRoleRequest (%s) now has a %q field -- #1494's closure rests on role "+
						"renaming being structurally unreachable (no field on either transport's update "+
						"request maps to models.Role.Name); adding one reopens #1494 and requires verifying "+
						"IsBuiltinRole (internal/core/auth_bootstrap.go, #294) actually blocks a rename "+
						"through this new field at every mutation call site before it ships, not after",
						src.transport, src.path, name.Name)
				}
			}
		}
	}
}

// findStructType returns the *ast.StructType for the first `type <name>
// struct {...}` declaration in f, and whether a type declaration named name
// was found at all (found=true, ok=false distinguishes "not a struct
// literal" -- e.g. a type alias -- from "no such type in this file").
func findStructType(f *ast.File, name string) (st *ast.StructType, found bool) {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != name {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			return st, ok
		}
	}
	return nil, false
}
