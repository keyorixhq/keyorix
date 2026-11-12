// machine_actor_argument_guard_test.go — CORE-ACTOR-RACE-1 item 3, the class guard
// for the bug #3990 fixed: a REST handler that calls a membership/grant core method
// must pass the REQUEST's machine-actor fact through, not a constant or some other
// value. The core methods refuse or ceiling-check a machine actor only when told it
// is one; a handler that passes `false` (or a human-only field) turns a machine
// token into a caller the core judges as a human.
//
// The family is DERIVED, not listed: every exported *KeyorixCore method in
// internal/core whose parameter list names one of machineActorParamNames. A
// method gaining such a parameter joins the guard without an edit here.
//
// What it recognises as "the request's machine actor" (an argument in that
// position), and nothing else:
//   - `<x>.ActorKind() == <pkg>.ActorTypeMachine` (either operand order);
//   - a call of the handlers package helpers isMachineActor(r) or machineID(r);
//   - `*<x>.MachineIdentityID` (the actor's own machine ID, dereferenced);
//   - an identifier of the enclosing function whose every explicit assignment is
//     one of the above (or the second result of creationGrantCtx), with at least
//     one such assignment; a `var x uint` with no value does not count as one.
//
// Scanned: every non-test .go file in server/http/handlers, every call whose
// selector names a family method and whose argument count matches the core
// signature (so a storage method of the same name and a different arity is not
// mistaken for it). Keyed by file and enclosing function.
//
// What it does not see: a call through a method value or an interface with a
// renamed method, a core method reached from outside server/http/handlers (gRPC,
// server/admin, the CLI), a value that is correct but built in another function and
// passed in, and core methods whose machine-actor fact rides in a request struct
// instead of a parameter (none in the scope list below today).
//
// It reports through guardrules.Rollout (docs/guard-rollout.d). The red proof is
// TestMachineActorArgumentGuard_Calibration, which runs the same scan over the
// planted fixtures below (written to a temp dir, so no repo-walking guard ever
// scans them) and does not go through Rollout.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// machineActorParamNames are the core parameter names that carry the request's
// machine actor: the bool "is the actor a machine" and the uint machine identity ID
// used for attribution and maker-checker (#1573).
var machineActorParamNames = []string{"actorIsMachine", "actorMachineID", "approverMachineID"}

// machineActorMutationScope is the premise this guard rests on: the core methods
// behind the REST routes that mutate membership or grants. Each must carry a
// machine-actor parameter (so it is in the derived family) and be called from a
// handler at least once (so the scan is not vacuous).
var machineActorMutationScope = []string{
	"AddProjectMember", "SetProjectMemberRole", // POST/PUT /projects/{id}/members
	"AssignUserRole", "AssignUserRoleWithExpiry", // POST /rbac/user-roles
	"AssignRoleToGroup", "AssignGroupRoleWithExpiry", // POST /groups/{id}/roles
	"SetUserRoles",           // PUT /users/{id}/roles
	"AssignMachineRole",      // POST /machine-identities/{id}/roles
	"AddUserToGroup",         // POST /groups/{id}/members
	"TransitionMembership",   // POST /projects/{id}/memberships/{mid}/...
	"AssignPermissionToRole", // POST /roles/{id}/permissions
}

// machineActorScopeWithoutParam: membership/grant mutations whose core method takes
// no machine-actor parameter, and why. Each must stay OUT of the derived family; one
// that gains the parameter must move to machineActorMutationScope.
var machineActorScopeWithoutParam = map[string]string{
	"RemoveProjectMember":  "DELETE /projects/{id}/members/{userId}: a revocation; machines are not refused (CORE-ACTOR-RACE-1 item 4, Needs coordinator)",
	"RemoveUserRole":       "DELETE /rbac/user-roles: a revocation",
	"RemoveUserFromGroup":  "DELETE /groups/{id}/members/{userId}: a revocation",
	"ShareSecret":          "POST /secrets/{id}/shares: the actor is SharedBy=userCtx.UserID, which is 0 for a machine and refused by the request's required validation",
	"ShareSecretWithGroup": "same route with is_group=true, same SharedBy validation",
}

// machineActorMethod is one family member: where its machine-actor parameter sits.
type machineActorMethod struct {
	Param string
	Index int // position in the flattened parameter list (ctx included)
	Arity int
}

// coreMachineActorMethods derives the family from the *KeyorixCore methods in the
// core family's sources (coreFamilySources, ADR-121 R5).
func coreMachineActorMethods(t testing.TB) map[string]machineActorMethod {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]machineActorMethod{}
	for _, path := range coreFamilySources(t) {
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || !fd.Name.IsExported() || secondFactorFuncKey(fd) != "KeyorixCore."+fd.Name.Name {
				continue
			}
			idx, arity, param := 0, 0, ""
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					arity++
					idx++
					continue
				}
				for _, n := range names {
					if param == "" && slices.Contains(machineActorParamNames, n.Name) {
						param = n.Name
						out[fd.Name.Name] = machineActorMethod{Param: n.Name, Index: idx}
					}
					idx++
					arity++
				}
			}
			if m, ok := out[fd.Name.Name]; ok && param != "" {
				m.Arity = arity
				out[fd.Name.Name] = m
			}
		}
	}
	return out
}

// isRequestMachineActorExpr reports whether e is one of the recognised forms (see
// the file comment); okIdents are the identifiers already proven to hold one.
func isRequestMachineActorExpr(e ast.Expr, okIdents map[string]bool) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return isRequestMachineActorExpr(e.X, okIdents)
	case *ast.BinaryExpr:
		if e.Op != token.EQL {
			return false
		}
		return (isActorKindCall(e.X) && isSelectorNamed(e.Y, "ActorTypeMachine")) ||
			(isActorKindCall(e.Y) && isSelectorNamed(e.X, "ActorTypeMachine"))
	case *ast.CallExpr:
		id, ok := e.Fun.(*ast.Ident)
		return ok && (id.Name == "isMachineActor" || id.Name == "machineID")
	case *ast.StarExpr:
		return isSelectorNamed(e.X, "MachineIdentityID")
	case *ast.Ident:
		return okIdents[e.Name]
	}
	return false
}

func isActorKindCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	return ok && len(call.Args) == 0 && isSelectorNamed(call.Fun, "ActorKind")
}

func isSelectorNamed(e ast.Expr, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

// machineActorIdents returns the identifiers of fd whose every explicit assignment
// is a recognised form, with at least one. Iterated to a fixed point so a chain of
// local copies resolves.
func machineActorIdents(fd *ast.FuncDecl) map[string]bool {
	type tally struct{ good, bad int }
	ok := map[string]bool{}
	for range 4 {
		seen := map[string]*tally{}
		mark := func(lhs ast.Expr, good bool) {
			id, isID := lhs.(*ast.Ident)
			if !isID || id.Name == "_" {
				return
			}
			if seen[id.Name] == nil {
				seen[id.Name] = &tally{}
			}
			if good {
				seen[id.Name].good++
			} else {
				seen[id.Name].bad++
			}
		}
		assign := func(lhs, rhs []ast.Expr) {
			if len(rhs) == 1 && len(lhs) == 2 {
				if call, isCall := rhs[0].(*ast.CallExpr); isCall {
					if fn, isID := call.Fun.(*ast.Ident); isID && fn.Name == "creationGrantCtx" {
						mark(lhs[1], true)
						return
					}
				}
			}
			if len(lhs) != len(rhs) {
				for _, l := range lhs {
					mark(l, false)
				}
				return
			}
			for i := range lhs {
				mark(lhs[i], isRequestMachineActorExpr(rhs[i], ok))
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				assign(n.Lhs, n.Rhs)
			case *ast.ValueSpec:
				if len(n.Values) > 0 {
					lhs := make([]ast.Expr, len(n.Names))
					for i, name := range n.Names {
						lhs[i] = name
					}
					assign(lhs, n.Values)
				}
			}
			return true
		})
		next := map[string]bool{}
		for name, c := range seen {
			if c.good > 0 && c.bad == 0 {
				next[name] = true
			}
		}
		if len(next) == len(ok) {
			return next
		}
		ok = next
	}
	return ok
}

// machineActorCallSite is one handler call of a family method.
type machineActorCallSite struct {
	Key    string // "file:Func|Method"
	Method string
	Arg    string
	OK     bool
}

// scanMachineActorCallSites returns every call of a family method under root.
func scanMachineActorCallSites(t testing.TB, root string, family map[string]machineActorMethod) []machineActorCallSite {
	t.Helper()
	var out []machineActorCallSite
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", rel, perr)
		}
		for _, decl := range f.Decls {
			fd, isFn := decl.(*ast.FuncDecl)
			if !isFn || fd.Body == nil {
				continue
			}
			okIdents := machineActorIdents(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				m, inFamily := family[sel.Sel.Name]
				if !inFamily || len(call.Args) != m.Arity {
					return true
				}
				arg := call.Args[m.Index]
				out = append(out, machineActorCallSite{
					Key:    filepath.ToSlash(rel) + ":" + secondFactorFuncKey(fd) + "|" + sel.Sel.Name,
					Method: sel.Sel.Name,
					Arg:    types.ExprString(arg),
					OK:     isRequestMachineActorExpr(arg, okIdents),
				})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key+out[i].Arg < out[j].Key+out[j].Arg })
	return out
}

func badMachineActorCallSites(sites []machineActorCallSite) []string {
	var bad []string
	for _, s := range sites {
		if !s.OK {
			bad = append(bad, s.Key+" passes "+s.Arg)
		}
	}
	return bad
}

func TestEveryMachineActorArgumentIsTheRequestActor(t *testing.T) {
	g := guardrules.Rollout(t)
	repo := srcpath.RepoRoot()
	family := coreMachineActorMethods(t)
	sites := scanMachineActorCallSites(t, filepath.Join(repo, "server", "http", "handlers"), family)

	// The premise: the scope is in the family and reached from a handler.
	called := map[string]bool{}
	for _, s := range sites {
		called[s.Method] = true
	}
	for _, name := range machineActorMutationScope {
		if _, ok := family[name]; !ok {
			g.Errorf("core.%s no longer takes one of %v: the machine-actor fact for its route is not passed as a parameter any more, so this guard cannot check it; restore the parameter or move the method to machineActorScopeWithoutParam with the reason", name, machineActorParamNames)
		}
	}
	for _, name := range []string{"AddProjectMember", "SetProjectMemberRole", "AssignUserRole", "AssignRoleToGroup", "AddUserToGroup"} {
		if !called[name] {
			g.Errorf("no call of core.%s found in server/http/handlers: the scan no longer reaches its route, so a pass would be vacuous", name)
		}
	}
	for name := range machineActorScopeWithoutParam {
		if m, ok := family[name]; ok {
			g.Errorf("core.%s now takes %s: move it from machineActorScopeWithoutParam to machineActorMutationScope", name, m.Param)
		}
	}
	for _, b := range badMachineActorCallSites(sites) {
		g.Errorf("%s as the machine-actor argument: pass the request's actor kind (userCtx.ActorKind() == core.ActorTypeMachine, isMachineActor(r), machineID(r)), or the core judges a machine token as a human (#3990 class)", b)
	}
	t.Logf("%d family methods, %d handler call sites checked", len(family), len(sites))
}

// Calibration pair: planted red sites are each reported, planted green sites (every
// recognised form) none. Not routed through Rollout, so it stays blocking.
func TestMachineActorArgumentGuard_Calibration(t *testing.T) {
	family := coreMachineActorMethods(t)
	fixtures := t.TempDir()
	writeTree(t, fixtures, map[string]string{"bad/handler.go": machineActorBadFixture, "good/handler.go": machineActorGoodFixture})

	bad := badMachineActorCallSites(scanMachineActorCallSites(t, filepath.Join(fixtures, "bad"), family))
	want := []string{
		"handler.go:FixtureHandler.addMemberConstant|AddProjectMember passes false",
		"handler.go:FixtureHandler.addMemberWrongField|AddProjectMember passes userCtx.IsAdmin",
		"handler.go:FixtureHandler.assignOverwritten|AssignUserRole passes isMachine",
		"handler.go:FixtureHandler.groupMemberLocalFalse|AddUserToGroup passes isMachine",
		"handler.go:FixtureHandler.rejectZeroMachine|RejectSecretAccessRequest passes 0",
		"handler.go:FixtureHandler.setRoleHumanKind|SetProjectMemberRole passes userCtx.ActorKind() == core.ActorTypeUser",
	}
	if !slices.Equal(bad, want) {
		t.Fatalf("planted red sites not reported as expected:\n got  %q\n want %q", bad, want)
	}

	goodSites := scanMachineActorCallSites(t, filepath.Join(fixtures, "good"), family)
	if len(goodSites) < 7 {
		t.Fatalf("good fixture: want at least 7 call sites scanned, got %d (the scan is not reaching them)", len(goodSites))
	}
	if extra := badMachineActorCallSites(goodSites); len(extra) != 0 {
		t.Fatalf("planted green sites were reported: %q", extra)
	}
}

// machineActorBadFixture is the planted red tree: every method passes something
// other than the request's machine actor. Parsed only, never compiled.
const machineActorBadFixture = `package fixture

func (h *FixtureHandler) addMemberConstant(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddProjectMember(r.Context(), userCtx.UserID, 1, 2, "viewer", false)
}

func (h *FixtureHandler) addMemberWrongField(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddProjectMember(r.Context(), userCtx.UserID, 1, 2, "viewer", userCtx.IsAdmin)
}

func (h *FixtureHandler) setRoleHumanKind(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.SetProjectMemberRole(r.Context(), userCtx.UserID, 1, 2, "viewer", userCtx.ActorKind() == core.ActorTypeUser)
}

func (h *FixtureHandler) assignOverwritten(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	isMachine := userCtx.ActorKind() == core.ActorTypeMachine
	isMachine = false
	_ = h.coreService.AssignUserRole(r.Context(), userCtx.UserID, 2, 3, core.Scope{}, isMachine)
}

func (h *FixtureHandler) groupMemberLocalFalse(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	isMachine := false
	_ = h.coreService.AddUserToGroup(r.Context(), userCtx.UserID, isMachine, 2, 3, 0)
}

func (h *FixtureHandler) rejectZeroMachine(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_, _ = h.coreService.RejectSecretAccessRequest(r.Context(), 7, userCtx.UserID, 0, "no")
}

// A storage method sharing a family name but not its arity is not a call site.
func (h *FixtureHandler) storageSameName(w http.ResponseWriter, r *http.Request) {
	_ = h.storage.AddProjectMember(r.Context(), 1, 2)
}
`

// machineActorGoodFixture is the planted green tree: one call per recognised form.
const machineActorGoodFixture = `package fixture

func (h *FixtureHandler) addMemberActorKind(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddProjectMember(r.Context(), userCtx.UserID, 1, 2, "viewer", userCtx.ActorKind() == core.ActorTypeMachine)
}

func (h *FixtureHandler) setRoleReversedOperands(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.SetProjectMemberRole(r.Context(), userCtx.UserID, 1, 2, "viewer", (core.ActorTypeMachine == userCtx.ActorKind()))
}

func (h *FixtureHandler) groupMemberHelper(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddUserToGroup(r.Context(), userCtx.UserID, isMachineActor(r), 2, 3, 0)
}

func (h *FixtureHandler) assignLocalCopy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	kind := userCtx.ActorKind() == core.ActorTypeMachine
	isMachine := kind
	_ = h.coreService.AssignUserRole(r.Context(), userCtx.UserID, 2, 3, core.Scope{}, isMachine)
}

func (h *FixtureHandler) createUserGrantCtx(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	ctx, isMachine := creationGrantCtx(r, userCtx)
	_, _ = h.coreService.CreateUserAudited(ctx, nil, userCtx.UserID, isMachine)
}

func (h *FixtureHandler) rejectDerefMachineID(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	var approverMachineID uint
	if actor.MachineIdentityID != nil {
		approverMachineID = *actor.MachineIdentityID
	}
	_, _ = h.coreService.RejectSecretAccessRequest(r.Context(), 7, actor.UserID, approverMachineID, "no")
}

func (h *FixtureHandler) approveHelperMachineID(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	_, _ = h.coreService.ApproveAccessRequestWithExpiry(r.Context(), 1, 2, actor.UserID, machineID(r), "viewer", 0)
}
`
