// machine_self_granter_tag_guard_test.go — guards
// INV-CORE-direct-machine-grant-handlers-tag-self-granter
// (internal/core/INVARIANTS.d/): every DIRECT HTTP handler or gRPC service
// method that reaches a KeyorixCore method applying the escalation-by-proxy
// ceiling (requireGranterHoldsRolePermissions / ...NoBaseline) must tag ctx
// with core.WithSelfMachineGranter on the machine-actor branch BEFORE that
// call. Without the tag the ceiling treats a directly authenticated machine
// like an untagged /system proxy relay and refuses unconditionally.
//
// How the population is derived (nothing here is a hand list):
//
//  1. Core call graph. Parse the non-test files of internal/core. A function
//     or *KeyorixCore method "reaches the ceiling" if its body (closures
//     included) calls one of granterCeilingSeeds, or calls another function
//     that does, to a fixpoint. A core function whose own body calls
//     WithSelfMachineGranter tags for itself (invitations, membership
//     lifecycle) and is a barrier: callers of it need no handler-side tag.
//  2. Transport call graph. For server/http/handlers and
//     server/grpc/services, a function "reaches" if it calls an exported
//     name from step 1, or a same-package function that reaches. Entry points
//     are every handler method registered in router.go (extractAllRouterRoutes)
//     and every exported method of server/grpc/services taking a
//     context.Context first.
//  3. For each reaching entry, walk its body and the reaching helpers it calls
//     in source order. A ceiling-reaching call is fine only if a tag was seen
//     before it: a direct core.WithSelfMachineGranter call, or a call to a
//     same-package "tagger" (a function whose body contains one, such as
//     creationGrantCtx). Call arguments count as evaluated before the call.
//     Separately, every WithSelfMachineGranter call anywhere in the transport
//     packages must sit under an `if` whose condition mentions the machine
//     actor kind (ActorTypeMachine/ActorKind or a *Machine* identifier).
//
// Call forms recognised: `f(...)`, `x.f(...)` and `pkg.f(...)`, matched by
// callee NAME (a collision can only over-report, never hide a site); calls
// whose receiver chain passes through Storage()/.storage are skipped (they are
// store methods, not KeyorixCore). NOT recognised, so a reviewer knows what
// the guard is blind to: a method value or function reference that is passed
// on without being called (`h.run(h.coreService.AssignX)`), calls through an
// interface-typed variable whose method name differs from the core method, a
// tag established in a different goroutine/closure than the call (flow
// insensitive: any earlier tag in the same function body counts), and a core
// function that tags for one ceiling call but not for another in the same body
// (the whole function is treated as self-tagging).
//
// Report-only on day one (docs/guard-rollout.d/, guard-rollout-contract.md).
package http

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var granterCeilingSeeds = map[string]bool{
	"requireGranterHoldsRolePermissions":           true,
	"requireGranterHoldsRolePermissionsNoBaseline": true,
	"RequireGranterHoldsRolePermissions":           true,
}

const selfGranterTagFn = "WithSelfMachineGranter"

// machineGranterTagExempt lists entry points that reach the ceiling with no
// tag for a stated reason (a route a machine actor can never reach). Empty on
// purpose: an entry is added only with a reviewed reason, and a stale entry
// fails the guard.
var machineGranterTagExempt = map[string]string{
	"SCIMHandler.CreateGroup": "SCIM provisioning authenticates with the SCIM bearer token, never as a machine actor; it calls core.ProvisionSCIMGroup with actorID 0 and no machine flag, which core exempts from the ceiling like the local CLI",
}

// minMachineGranterTaggedEntries is the non-vacuity floor: the invariant lists
// 12 known-good call sites in 12 handlers/methods; losing most of them from
// the analysis means the walk broke, not that the code improved.
const minMachineGranterTaggedEntries = 10

func granterParseDir(t testing.TB, fset *token.FileSet, dir string) []*ast.File {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var files []*ast.File
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", n, err)
		}
		files = append(files, f)
	}
	return files
}

func granterParseSources(t testing.TB, fset *token.FileSet, srcs map[string]string) []*ast.File {
	t.Helper()
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	var files []*ast.File
	for _, n := range names {
		f, err := parser.ParseFile(fset, n, srcs[n], parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing synthetic %s: %v", n, err)
		}
		files = append(files, f)
	}
	return files
}

// granterCallee returns the called name and whether the receiver chain passes
// through a Storage()/.storage accessor.
func granterCallee(call *ast.CallExpr) (name string, viaStorage bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, false
	case *ast.SelectorExpr:
		x := fn.X
		for {
			switch v := x.(type) {
			case *ast.CallExpr:
				if s, ok := v.Fun.(*ast.SelectorExpr); ok {
					if s.Sel.Name == "Storage" {
						return fn.Sel.Name, true
					}
					x = s.X
					continue
				}
				return fn.Sel.Name, false
			case *ast.SelectorExpr:
				if v.Sel.Name == "storage" || v.Sel.Name == "Storage" {
					return fn.Sel.Name, true
				}
				x = v.X
				continue
			case *ast.ParenExpr:
				x = v.X
				continue
			case *ast.StarExpr:
				x = v.X
				continue
			}
			return fn.Sel.Name, false
		}
	}
	return "", false
}

func granterRecvName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func granterIndex(files []*ast.File, keep func(*ast.FuncDecl) bool) map[string][]*ast.FuncDecl {
	idx := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && keep(fd) {
				idx[fd.Name.Name] = append(idx[fd.Name.Name], fd)
			}
		}
	}
	return idx
}

// granterBodyCalls reports whether body contains a non-storage call to any
// name in set.
func granterBodyCalls(body *ast.BlockStmt, set map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && !found {
			if name, via := granterCallee(c); !via && set[name] {
				found = true
			}
		}
		return !found
	})
	return found
}

// granterFixpoint grows seed with every function in idx whose body calls a
// member, skipping names in barrier.
func granterFixpoint(idx map[string][]*ast.FuncDecl, seed, barrier map[string]bool) map[string]bool {
	reach := map[string]bool{}
	for n := range seed {
		reach[n] = true
	}
	for changed := true; changed; {
		changed = false
		for name, decls := range idx {
			if reach[name] || barrier[name] {
				continue
			}
			for _, fd := range decls {
				if granterBodyCalls(fd.Body, reach) {
					reach[name] = true
					changed = true
					break
				}
			}
		}
	}
	return reach
}

// coreGranterReachers returns the exported names of core functions that reach
// the ceiling without tagging for themselves.
func coreGranterReachers(core []*ast.File) map[string]bool {
	idx := granterIndex(core, func(fd *ast.FuncDecl) bool {
		r := granterRecvName(fd)
		return r == "" || r == "KeyorixCore"
	})
	selfTag := map[string]bool{}
	for name, decls := range idx {
		for _, fd := range decls {
			if granterBodyCalls(fd.Body, map[string]bool{selfGranterTagFn: true}) {
				selfTag[name] = true
			}
		}
	}
	reach := granterFixpoint(idx, granterCeilingSeeds, selfTag)
	out := map[string]bool{}
	for n := range reach {
		if ast.IsExported(n) && !selfTag[n] {
			out[n] = true
		}
	}
	return out
}

type granterAnalysis struct {
	coreReach  map[string]bool // exported core names reaching the ceiling
	entries    map[string]bool // entry points that reach the ceiling
	tagged     map[string]bool // reaching entries with every site tagged
	violations []string
}

func granterMentionsMachine(e ast.Expr) bool {
	hit := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if id.Name == "ActorTypeMachine" || id.Name == "ActorKind" || strings.Contains(strings.ToLower(id.Name), "machine") {
				hit = true
			}
		}
		return !hit
	})
	return hit
}

// analyzeGranterTags runs steps 2-3 of the doc comment over transport files.
func analyzeGranterTags(fset *token.FileSet, coreReach map[string]bool, files []*ast.File, isEntry func(*ast.FuncDecl) bool) granterAnalysis {
	res := granterAnalysis{coreReach: coreReach, entries: map[string]bool{}, tagged: map[string]bool{}}
	idx := granterIndex(files, func(*ast.FuncDecl) bool { return true })
	tagSet := map[string]bool{selfGranterTagFn: true}

	taggers := map[string]bool{}
	for name, decls := range idx {
		for _, fd := range decls {
			if granterBodyCalls(fd.Body, tagSet) {
				taggers[name] = true
			}
		}
	}
	// Machine-branch rule for every tag call in the package.
	seenViol := map[string]bool{}
	addViol := func(s string) {
		if !seenViol[s] {
			seenViol[s] = true
			res.violations = append(res.violations, s)
		}
	}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			var stack []ast.Node
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				if c, ok := n.(*ast.CallExpr); ok {
					if name, _ := granterCallee(c); name == selfGranterTagFn {
						onBranch := false
						for _, a := range stack {
							if ifs, ok := a.(*ast.IfStmt); ok && granterMentionsMachine(ifs.Cond) {
								onBranch = true
							}
						}
						if !onBranch {
							addViol(fmt.Sprintf("%s: %s calls %s outside an `if` on the machine actor kind", fset.Position(c.Pos()), fd.Name.Name, selfGranterTagFn))
						}
					}
				}
				stack = append(stack, n)
				return true
			})
		}
	}

	exported := map[string]bool{}
	for n := range coreReach {
		exported[n] = true
	}
	localReach := granterFixpoint(idx, map[string]bool{}, nil)
	// Seed local reach with direct core calls, then close over local calls.
	for name, decls := range idx {
		for _, fd := range decls {
			if granterBodyCalls(fd.Body, exported) {
				localReach[name] = true
			}
		}
	}
	localReach = granterFixpoint(idx, localReach, nil)

	type visitKey struct {
		fd        *ast.FuncDecl
		inherited bool
	}
	for name, decls := range idx {
		for _, entry := range decls {
			if !isEntry(entry) || !localReach[name] {
				continue
			}
			label := name
			if r := granterRecvName(entry); r != "" {
				label = r + "." + name
			}
			res.entries[label] = true
			visited := map[visitKey]bool{}
			clean := true
			var walk func(fd *ast.FuncDecl, inherited bool)
			walk = func(fd *ast.FuncDecl, inherited bool) {
				k := visitKey{fd, inherited}
				if visited[k] {
					return
				}
				visited[k] = true
				tagged := inherited
				var stack []ast.Node
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if n == nil {
						top := stack[len(stack)-1]
						stack = stack[:len(stack)-1]
						c, ok := top.(*ast.CallExpr)
						if !ok {
							return true
						}
						cn, via := granterCallee(c)
						switch {
						case cn == selfGranterTagFn || taggers[cn]:
							tagged = true
						case via:
						case exported[cn]:
							if !tagged {
								clean = false
								addViol(fmt.Sprintf("%s: entry %s reaches the grant ceiling via %s() with no preceding %s on the machine-actor branch", fset.Position(c.Pos()), label, cn, selfGranterTagFn))
							}
						case localReach[cn] && cn != fd.Name.Name:
							for _, h := range idx[cn] {
								walk(h, tagged)
							}
						}
						return true
					}
					stack = append(stack, n)
					return true
				})
			}
			walk(entry, false)
			if clean {
				res.tagged[label] = true
			}
		}
	}
	sort.Strings(res.violations)
	return res
}

func grpcServiceEntry(fd *ast.FuncDecl) bool {
	if fd.Recv == nil || !ast.IsExported(fd.Name.Name) || fd.Type.Params == nil || len(fd.Type.Params.List) == 0 {
		return false
	}
	sel, ok := fd.Type.Params.List[0].Type.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Context"
}

// TestEveryDirectMachineGrantEntryTagsSelfGranter is the guard for
// INV-CORE-direct-machine-grant-handlers-tag-self-granter.
func TestEveryDirectMachineGrantEntryTagsSelfGranter(t *testing.T) {
	g := guardrules.Rollout(t)
	fset := token.NewFileSet()

	coreReach := coreGranterReachers(granterParseDir(t, fset, filepath.Join("..", "..", "internal", "core")))
	if len(coreReach) < 15 {
		t.Fatalf("only %d exported core functions reach the grant ceiling; the core call-graph walk is broken", len(coreReach))
	}

	routes := extractAllRouterRoutes(t, filepath.Join(".", "router.go"))
	httpEntries := map[string]bool{}
	for _, r := range routes {
		if r.Handler != "" {
			httpEntries[r.Handler] = true
		}
	}
	httpRes := analyzeGranterTags(fset, coreReach, granterParseDir(t, fset, handlersDir),
		func(fd *ast.FuncDecl) bool { return httpEntries[fd.Name.Name] })
	grpcRes := analyzeGranterTags(fset, coreReach, granterParseDir(t, fset, filepath.Join("..", "grpc", "services")), grpcServiceEntry)

	taggedCount := len(httpRes.tagged) + len(grpcRes.tagged)
	t.Logf("machine self-granter guard: %d core reachers; %d HTTP + %d gRPC entries reach the ceiling, %d tagged",
		len(coreReach), len(httpRes.entries), len(grpcRes.entries), taggedCount)
	if taggedCount < minMachineGranterTaggedEntries {
		t.Fatalf("only %d tagged ceiling-reaching entries found, want >= %d; the transport walk is broken", taggedCount, minMachineGranterTaggedEntries)
	}

	seen := map[string]bool{}
	for _, res := range []granterAnalysis{httpRes, grpcRes} {
		for _, v := range res.violations {
			ok := false
			for name := range machineGranterTagExempt {
				if strings.Contains(v, "entry "+name+" ") {
					ok = true
					seen[name] = true
				}
			}
			if !ok {
				g.Errorf("%s", v)
			}
		}
	}
	for name, why := range machineGranterTagExempt {
		if !seen[name] {
			g.Errorf("machineGranterTagExempt[%q] (%s) no longer reproduces; remove it", name, why)
		}
	}
}

const granterSynthCore = `package core
type KeyorixCore struct{}
func (c *KeyorixCore) requireGranterHoldsRolePermissions() error { return nil }
func (c *KeyorixCore) AssignThing() error { return c.requireGranterHoldsRolePermissions() }
func (c *KeyorixCore) AssignViaHelper() error { return c.AssignThing() }
func (c *KeyorixCore) SelfTagging() error {
	ctx = WithSelfMachineGranter(ctx, 1)
	return c.requireGranterHoldsRolePermissions()
}
func (c *KeyorixCore) Unrelated() error { c.storage.AssignThing(); return nil }
`

// TestMachineSelfGranterGuardDetectsOmittedTag proves the detector goes both
// red and green against synthetic handler sources (go/parser, no fixture
// package): a handler that omits the tag must be reported.
func TestMachineSelfGranterGuardDetectsOmittedTag(t *testing.T) {
	cases := []struct {
		name     string
		handler  string
		wantViol int
		wantTag  bool
	}{
		{"omits tag", `package h
func (h *H) Bad() { h.core.AssignThing(ctx) }`, 1, false},
		{"tag on machine branch first", `package h
func (h *H) Good() {
	if actor.ActorKind() == core.ActorTypeMachine { ctx = core.WithSelfMachineGranter(ctx, 1) }
	h.core.AssignThing(ctx)
}`, 0, true},
		{"tag after the call", `package h
func (h *H) Late() {
	h.core.AssignThing(ctx)
	if actor.ActorKind() == core.ActorTypeMachine { ctx = core.WithSelfMachineGranter(ctx, 1) }
}`, 1, false},
		{"tag not on machine branch", `package h
func (h *H) Unconditional() {
	ctx = core.WithSelfMachineGranter(ctx, 1)
	h.core.AssignThing(ctx)
}`, 1, true},
		{"tagger helper in the call argument", `package h
func grantCtx() context.Context {
	if k == core.ActorTypeMachine { return core.WithSelfMachineGranter(ctx, 1) }
	return ctx
}
func (h *H) Good() { h.core.AssignThing(grantCtx()) }`, 0, true},
		{"untagged call through a local helper", `package h
func (h *H) run() { h.core.AssignViaHelper() }
func (h *H) Bad() { h.run() }`, 1, false},
		{"tag before a local helper", `package h
func (h *H) run() { h.core.AssignViaHelper() }
func (h *H) Good() {
	if isMachine { ctx = core.WithSelfMachineGranter(ctx, 1) }
	h.run()
}`, 0, true},
		{"core method that tags for itself needs no handler tag", `package h
func (h *H) Fine() { h.core.SelfTagging() }`, 0, false},
		{"storage method with the same name is not a core call", `package h
func (h *H) Fine() { h.core.Storage().AssignThing() }`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			reach := coreGranterReachers(granterParseSources(t, fset, map[string]string{"core.go": granterSynthCore}))
			for _, want := range []string{"AssignThing", "AssignViaHelper"} {
				if !reach[want] {
					t.Fatalf("synthetic core: %s not detected as reaching the ceiling: %v", want, reach)
				}
			}
			if reach["SelfTagging"] || reach["Unrelated"] {
				t.Fatalf("synthetic core: self-tagging/unrelated function wrongly reaches: %v", reach)
			}
			res := analyzeGranterTags(fset, reach, granterParseSources(t, fset, map[string]string{"h.go": tc.handler}),
				func(fd *ast.FuncDecl) bool { return fd.Recv != nil && ast.IsExported(fd.Name.Name) })
			for _, v := range res.violations {
				t.Logf("guard would report: %s", v)
			}
			if got := len(res.tagged) > 0; got != tc.wantTag {
				t.Errorf("tagged entries = %v, want tagged=%v", res.tagged, tc.wantTag)
			}
			if len(res.violations) != tc.wantViol {
				t.Errorf("got %d violation(s) %v, want %d", len(res.violations), res.violations, tc.wantViol)
			}
		})
	}
}
