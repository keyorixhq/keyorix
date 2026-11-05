// Command authzmatrix derives the cross-layer operation matrix the authz
// differential harness (server/authzdiff) is built on: for every mutating or
// secret-reading operation, which exported *core.KeyorixCore entry point(s) it
// reaches, from which REST route(s), and from which gRPC method(s).
//
// Everything is derived from type-checked code, never from file or symbol
// names:
//
//   - REST population: scripts/e2e/routes.json (itself AST-derived from
//     router.go and kept current by TestRouteInventoryIsCurrent). For each row
//     the handler is the LAST argument of the chi registration call on that
//     router.go line, resolved through go/types to the function or method value
//     it denotes (a method value, a plain function, or a factory call whose
//     returned closure is reached through the factory's body).
//   - gRPC population: every pb.Register<X>Server(s, impl) call in server/grpc;
//     the implementation methods are looked up in impl's static type's method
//     set for every method of the <X>Server interface (the registration's
//     parameter type), and named by the generated <X>_<M>_FullMethodName const.
//   - Mutating: the key is in server/faultops' generated knownOperations (read
//     from that file's AST). That set is HTTP-verb based for REST and a
//     read-prefix classifier for gRPC (faultops' isMutatingGRPCMethod) — this
//     tool inherits that classifier's blind spots and reports gRPC methods whose
//     core entry is shared with a mutating REST route but are not in the set.
//   - Secret-reading (secret-VALUE read): the operation reaches, inside core,
//     (a) (*KeyorixCore).decryptVersionValue — the secret/version value path —
//     or (b) a GetSecret invoke on ports.Connector/connect.Connector — a
//     federated read. (b) was added after (a) alone missed
//     ConnectService.ReadSecret. Any OTHER decrypt reached (a Decrypt* invoke
//     on a ports interface — core's only route to the encryptor since ADR-109 —
//     or a static (*encryption.Service).Decrypt* call) is reported as
//     decrypts_internally and does not by itself put an op in scope: the same
//     encryptor decrypts MFA secrets, notification URLs and dynamic-secret
//     admin credentials that are never returned to the caller.
//
// Reachability: an SSA walk from each handler/RPC implementation that follows
// (1) static calls, (2) every *ssa.Function used as an operand (closures, method
// values, callbacks), and (3) interface invokes whose interface *KeyorixCore
// implements (resolved to the concrete core method). It crosses any package in
// this module except internal/core; on entering an exported *KeyorixCore method
// it records that method as a core entry point and stops. Invokes on
// internal/core/storage.Storage outside core are recorded as raw-storage calls.
//
// What it does NOT see, by design: interface invokes on interfaces *KeyorixCore
// does not implement (other than storage.Storage), reflection, and calls made
// through values stored in maps/struct fields of interface type. Routes whose
// walk reaches no core entry point are listed as residue, never dropped.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const (
	modPath     = "github.com/keyorixhq/keyorix"
	corePkg     = modPath + "/internal/core"
	coreStorage = modPath + "/internal/core/storage"
	encPkg      = modPath + "/internal/encryption"
	connectPkg  = modPath + "/internal/connect"
	portsPkg    = modPath + "/internal/core/ports"
	pbPkg       = modPath + "/server/proto/pb"
	httpPkg     = modPath + "/server/http"
	grpcPkg     = modPath + "/server/grpc"
)

// Op is one REST route or gRPC method in the population.
type Op struct {
	Key           string   `json:"key"` // "REST POST /api/v1/..." or "GRPC keyorix.v1.Svc.Method"
	Layer         string   `json:"layer"`
	Handler       string   `json:"handler"`
	GatePerms     []string `json:"gate_perms,omitempty"`
	Gated         bool     `json:"gated"`
	Mutating      bool     `json:"mutating"`
	SecretReading bool     `json:"secret_reading"`
	CoreEntries   []string `json:"core_entries"`
	RawStorage    []string `json:"raw_storage,omitempty"`
	GuardReach    []string `json:"guard_reach,omitempty"` // FIX-1 entries + guardFuncs reached transitively in core
	SeedGap       string   `json:"seed_gap,omitempty"`
	// DecryptsInternally: reaches a decrypt that is not a secret-value read
	// (see decryptKinds). Reported only; not in scope by itself.
	DecryptsInternally bool   `json:"decrypts_internally,omitempty"`
	Unresolved         string `json:"unresolved,omitempty"`
}

type route struct {
	Method    string   `json:"method"`
	Pattern   string   `json:"pattern"`
	Gated     bool     `json:"gated"`
	GatePerms []string `json:"gate_perms"`
	Line      int      `json:"router_go_line"`
}

type analyzer struct {
	prog      *ssa.Program
	coreNamed *types.Named
	storIface *types.Named
	// memo of the core-entry/raw-storage reach of each non-core function
	memo map[*ssa.Function]*reachSet
	// memo: exported core method -> reaches a secret decryption primitive
	decryptMemo    map[*ssa.Function]bool
	anyDecryptMemo map[*ssa.Function]bool
	// memo: exported core method -> exported core methods it reaches inside core
	innerMemo map[*ssa.Function]map[string]bool
	// refusal classification (refusal.go)
	sentinels   map[*ssa.Global]bool
	refusalMemo map[*ssa.Function]refusal
}

type reachSet struct {
	core map[*ssa.Function]bool
	raw  map[string]bool
}

func main() {
	root := flag.String("root", ".", "repo root")
	jsonOut := flag.String("json", "", "write the full op list as JSON here")
	mdOut := flag.String("md", "", "write the markdown matrix here")
	flag.Parse()

	abs, err := filepath.Abs(*root)
	must(err)
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Dir: abs, Tests: false}
	pkgs, err := packages.Load(cfg, "./server/http", "./server/grpc", "./internal/core")
	must(err)
	if packages.PrintErrors(pkgs) > 0 {
		fatalf("package load errors")
	}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		loadedSyntax[p.PkgPath] = &pkgView{syntax: p.Syntax, info: p.TypesInfo}
	})
	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	a := &analyzer{prog: prog, memo: map[*ssa.Function]*reachSet{}, decryptMemo: map[*ssa.Function]bool{}, anyDecryptMemo: map[*ssa.Function]bool{}, innerMemo: map[*ssa.Function]map[string]bool{}, refusalMemo: map[*ssa.Function]refusal{}}
	a.coreNamed = lookupNamed(prog, corePkg, "KeyorixCore")
	a.storIface = lookupNamed(prog, coreStorage, "Storage")

	known := readKnownOperations(filepath.Join(abs, "server/faultops/inventory_registry_generated_test.go"))

	var ops []*Op
	ops = append(ops, a.restOps(abs, known)...)
	ops = append(ops, a.grpcOps(known)...)

	coreRows := a.buildRows(ops)

	if *jsonOut != "" {
		b, err := json.MarshalIndent(struct {
			Ops  []*Op      `json:"ops"`
			Rows []*CoreRow `json:"rows"`
		}{ops, coreRows}, "", "  ")
		must(err)
		must(os.WriteFile(*jsonOut, append(b, '\n'), 0o644))
	}
	if green := calibrateSelfTest(ops); len(green) > 0 {
		fatalf("calibration self-test: planted mismatches stayed green: %v", green)
	}
	calib, calibOK := calibrate(ops)
	if *mdOut != "" {
		md := renderMarkdown(ops, coreRows) + "\n## Calibration against the 8 FIX-1 guards\n\n" + calib
		must(os.WriteFile(*mdOut, []byte(md), 0o644))
	}
	fmt.Fprintf(os.Stderr, "ops=%d rows=%d calibration_ok=%v\n", len(ops), len(coreRows), calibOK)
	if !calibOK {
		fmt.Fprint(os.Stderr, calib)
		os.Exit(2)
	}
}

// ---------- REST ----------

func (a *analyzer) restOps(root string, known map[string]bool) []*Op {
	raw, err := os.ReadFile(filepath.Join(root, "scripts/e2e/routes.json"))
	must(err)
	var routes []route
	must(json.Unmarshal(raw, &routes))

	hp := a.pkg(httpPkg)
	var routerFile *ast.File
	for _, f := range hp.syntax {
		if strings.HasSuffix(a.prog.Fset.File(f.Pos()).Name(), "/router.go") {
			routerFile = f
		}
	}
	if routerFile == nil {
		fatalf("router.go not found in %s", httpPkg)
	}
	tf := a.prog.Fset.File(routerFile.Pos())

	// chi registration calls by line: the outermost call whose selector is a
	// chi verb method and whose receiver is a chi.Router/chi.Mux value.
	byLine := map[int]*ast.CallExpr{}
	ast.Inspect(routerFile, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || !chiVerb[sel.Sel.Name] || len(ce.Args) < 2 {
			return true
		}
		if !isChiRouter(hp.info.TypeOf(sel.X)) {
			return true
		}
		// routes.json records the statement's start line; a chained
		// r.With(...).\n Post(...) puts the verb on a later line. Index both.
		for _, ln := range []int{tf.Line(ce.Pos()), tf.Line(sel.Sel.Pos())} {
			if _, seen := byLine[ln]; !seen {
				byLine[ln] = ce
			}
		}
		return true
	})

	var ops []*Op
	for _, r := range routes {
		key := "REST " + r.Method + " " + r.Pattern
		// faultops keys come from chi.Walk, which renders a sub-router root
		// with a trailing slash ("/api/v1/groups/"); routes.json does not.
		inKnown := known[normKey(key)]
		mutVerb := r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE"
		op := &Op{Key: key, Layer: "rest", Gated: r.Gated, GatePerms: r.GatePerms, Mutating: mutVerb || inKnown}
		if mutVerb && !inKnown {
			op.SeedGap = "mutating verb but absent from faultops knownOperations"
		}
		ce := byLine[r.Line]
		if ce == nil {
			op.Unresolved = fmt.Sprintf("no chi registration call on router.go:%d", r.Line)
			ops = append(ops, op)
			continue
		}
		hexpr := ce.Args[len(ce.Args)-1]
		op.Handler = types.ExprString(hexpr)
		fns := a.exprFuncs(hp, hexpr)
		if len(fns) == 0 {
			op.Unresolved = "handler expression does not resolve to a function: " + op.Handler
		}
		a.fill(op, fns)
		ops = append(ops, op)
	}
	return ops
}

var chiVerb = map[string]bool{"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true, "Head": true, "Options": true, "Method": true, "MethodFunc": true, "Handle": true, "HandleFunc": true, "Mount": true}

func isChiRouter(t types.Type) bool {
	if t == nil {
		return false
	}
	s := t.String()
	return strings.Contains(s, "go-chi/chi") && (strings.HasSuffix(s, ".Router") || strings.HasSuffix(s, ".Mux"))
}

// exprFuncs resolves a handler expression to the SSA function(s) whose bodies
// run when the route is served: a method value/func ident maps to that func;
// a call (factory) maps to the factory (its returned closure is reached as an
// operand of the factory body); a conversion like http.HandlerFunc(x) recurses
// into x.
func (a *analyzer) exprFuncs(p *pkgView, e ast.Expr) []*ssa.Function {
	switch x := ast.Unparen(e).(type) {
	case *ast.SelectorExpr:
		if sel := p.info.Selections[x]; sel != nil {
			if f, ok := sel.Obj().(*types.Func); ok {
				if fns := a.funcsFor(f, sel.Recv()); len(fns) > 0 {
					return fns
				}
				// method value on an interface (factory().ServeHTTP): the
				// concrete handler is built by the receiver expression.
				return a.exprFuncs(p, x.X)
			}
		}
		if f, ok := p.info.Uses[x.Sel].(*types.Func); ok {
			return a.funcsFor(f, nil)
		}
	case *ast.Ident:
		if f, ok := p.info.Uses[x].(*types.Func); ok {
			return a.funcsFor(f, nil)
		}
	case *ast.CallExpr:
		if tv, ok := p.info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
			return a.exprFuncs(p, x.Args[0])
		}
		out := a.exprFuncs(p, x.Fun)
		for _, arg := range x.Args { // e.g. handlers.Wrap(h.Method)
			out = append(out, a.exprFuncs(p, arg)...)
		}
		return out
	case *ast.FuncLit:
		// an inline closure in router.go: find its SSA anon func by position
		if fn := a.anonAt(x.Pos()); fn != nil {
			return []*ssa.Function{fn}
		}
	}
	return nil
}

func (a *analyzer) funcsFor(f *types.Func, recv types.Type) []*ssa.Function {
	if fn := a.prog.FuncValue(f); fn != nil {
		return []*ssa.Function{fn}
	}
	if recv != nil {
		if ms := a.prog.MethodSets.MethodSet(recv); ms != nil {
			if s := ms.Lookup(f.Pkg(), f.Name()); s != nil {
				if fn := a.prog.MethodValue(s); fn != nil {
					return []*ssa.Function{fn}
				}
			}
		}
	}
	return nil
}

func (a *analyzer) anonAt(pos token.Pos) *ssa.Function {
	for fn := range ssautil.AllFunctions(a.prog) {
		if fn.Parent() != nil && fn.Syntax() != nil && fn.Syntax().Pos() == pos {
			return fn
		}
	}
	return nil
}

// ---------- gRPC ----------

func (a *analyzer) grpcOps(known map[string]bool) []*Op {
	gp := a.pkg(grpcPkg)
	pb := a.typesPkg(pbPkg)
	var ops []*Op
	for _, f := range gp.syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok || len(ce.Args) != 2 {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			fobj, ok := gp.info.Uses[sel.Sel].(*types.Func)
			if !ok || fobj.Pkg() == nil || fobj.Pkg().Path() != pbPkg || !strings.HasPrefix(fobj.Name(), "Register") || !strings.HasSuffix(fobj.Name(), "Server") {
				return true
			}
			svc := strings.TrimSuffix(strings.TrimPrefix(fobj.Name(), "Register"), "Server") // e.g. RoleService
			ifaceT := fobj.Type().(*types.Signature).Params().At(1).Type()
			iface, ok := ifaceT.Underlying().(*types.Interface)
			if !ok {
				fatalf("%s: second param is not an interface", fobj.Name())
			}
			implT := gp.info.TypeOf(ce.Args[1])
			ms := a.prog.MethodSets.MethodSet(implT)
			for m := range iface.Methods() {
				if strings.HasPrefix(m.Name(), "mustEmbed") {
					continue
				}
				full := svc + "." + m.Name()
				if c, ok := pb.Scope().Lookup(svc + "_" + m.Name() + "_FullMethodName").(*types.Const); ok {
					s := constant.StringVal(c.Val()) // "/keyorix.v1.RoleService/AssignRole"
					full = strings.Replace(strings.TrimPrefix(s, "/"), "/", ".", 1)
				}
				key := "GRPC " + full
				op := &Op{Key: key, Layer: "grpc", Handler: types.TypeString(implT, nil) + "." + m.Name(), Mutating: known[key]}
				s := ms.Lookup(m.Pkg(), m.Name())
				if s == nil {
					op.Unresolved = "implementation method not in method set"
					ops = append(ops, op)
					continue
				}
				fn := a.prog.MethodValue(s)
				if fn != nil && fn.Synthetic != "" && len(fn.Blocks) == 0 {
					op.Unresolved = "method is synthetic (likely Unimplemented embed)"
				}
				if fn != nil && isUnimplementedPromoted(s) {
					op.Unresolved = "promoted from Unimplemented<X>Server (RPC not implemented)"
				}
				a.fill(op, []*ssa.Function{fn})
				ops = append(ops, op)
			}
			return true
		})
	}
	return ops
}

func isUnimplementedPromoted(s *types.Selection) bool {
	if len(s.Index()) < 2 {
		return false
	}
	recv := s.Obj().(*types.Func).Type().(*types.Signature).Recv()
	return recv != nil && strings.Contains(types.TypeString(recv.Type(), nil), "Unimplemented")
}

// ---------- reachability ----------

func (a *analyzer) fill(op *Op, roots []*ssa.Function) {
	core := map[*ssa.Function]bool{}
	raw := map[string]bool{}
	for _, r := range roots {
		if r == nil {
			continue
		}
		rs := a.reach(r, map[*ssa.Function]bool{})
		for f := range rs.core {
			core[f] = true
		}
		for s := range rs.raw {
			raw[s] = true
		}
	}
	gr := map[string]bool{}
	for f := range core {
		op.CoreEntries = append(op.CoreEntries, f.Name())
		vr, anyDec := a.decryptKinds(f)
		if vr {
			op.SecretReading = true
		}
		if anyDec && !vr {
			op.DecryptsInternally = true
		}
		inner := a.innerNames(f)
		for _, g := range calibrationNames() {
			if inner[g] || f.Name() == g {
				gr[g] = true
			}
		}
	}
	for g := range gr {
		op.GuardReach = append(op.GuardReach, g)
	}
	sort.Strings(op.GuardReach)
	sort.Strings(op.CoreEntries)
	for s := range raw {
		op.RawStorage = append(op.RawStorage, s)
	}
	sort.Strings(op.RawStorage)
}

func (a *analyzer) isCore(fn *ssa.Function) bool {
	o := fn
	if fn.Origin() != nil {
		o = fn.Origin()
	}
	return o.Pkg != nil && o.Pkg.Pkg.Path() == corePkg
}

func (a *analyzer) isExportedCoreMethod(fn *ssa.Function) bool {
	if fn.Signature.Recv() == nil || !fn.Object().Exported() {
		return false
	}
	t := fn.Signature.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	return types.Identical(t, a.coreNamed)
}

func inModule(fn *ssa.Function) bool {
	o := fn
	if fn.Origin() != nil {
		o = fn.Origin()
	}
	if o.Pkg == nil {
		// synthetic wrappers (bound/thunk) carry no package: follow them
		return o.Synthetic != ""
	}
	return strings.HasPrefix(o.Pkg.Pkg.Path(), modPath+"/")
}

func (a *analyzer) reach(fn *ssa.Function, onStack map[*ssa.Function]bool) *reachSet {
	if rs, ok := a.memo[fn]; ok {
		return rs
	}
	rs := &reachSet{core: map[*ssa.Function]bool{}, raw: map[string]bool{}}
	if onStack[fn] {
		return rs // cycle: partial; caller merges
	}
	onStack[fn] = true
	defer delete(onStack, fn)

	visit := func(g *ssa.Function) {
		if g == nil {
			return
		}
		if a.isCore(g) {
			if a.isExportedCoreMethod(g) {
				rs.core[g] = true
			}
			return
		}
		if !inModule(g) {
			return
		}
		sub := a.reach(g, onStack)
		for f := range sub.core {
			rs.core[f] = true
		}
		for s := range sub.raw {
			rs.raw[s] = true
		}
	}
	for _, b := range fn.Blocks {
		for _, ins := range b.Instrs {
			if ci, ok := ins.(ssa.CallInstruction); ok {
				c := ci.Common()
				if c.IsInvoke() {
					it := c.Value.Type()
					if a.storIface != nil && types.Identical(it, a.storIface) {
						rs.raw[c.Method.Name()] = true
					} else if ii, ok := it.Underlying().(*types.Interface); ok && types.Implements(types.NewPointer(a.coreNamed), ii) {
						visit(a.coreMethod(c.Method.Name()))
					}
				} else if callee := c.StaticCallee(); callee != nil {
					visit(callee)
				}
			}
			var opsBuf []*ssa.Value
			for _, v := range ins.Operands(opsBuf) {
				if v == nil || *v == nil {
					continue
				}
				if g, ok := (*v).(*ssa.Function); ok {
					visit(g)
				}
			}
		}
	}
	for _, anon := range fn.AnonFuncs {
		visit(anon)
	}
	a.memo[fn] = rs
	return rs
}

func (a *analyzer) coreMethod(name string) *ssa.Function {
	ms := a.prog.MethodSets.MethodSet(types.NewPointer(a.coreNamed))
	if s := ms.Lookup(a.coreNamed.Obj().Pkg(), name); s != nil {
		return a.prog.MethodValue(s)
	}
	return nil
}

// innerCore walks inside internal/core from fn (static calls + function
// operands), calling hit on every function reached.
func (a *analyzer) innerCore(fn *ssa.Function, seen map[*ssa.Function]bool, hit func(*ssa.Function, *ssa.CallCommon)) {
	if fn == nil || seen[fn] {
		return
	}
	seen[fn] = true
	for _, b := range fn.Blocks {
		for _, ins := range b.Instrs {
			if ci, ok := ins.(ssa.CallInstruction); ok {
				c := ci.Common()
				if callee := c.StaticCallee(); callee != nil {
					hit(callee, c)
					if a.isCore(callee) {
						a.innerCore(callee, seen, hit)
					}
				} else if c.IsInvoke() {
					hit(nil, c) // interface invoke: callee unknown, method in c.Method
				}
			}
			var buf []*ssa.Value
			for _, v := range ins.Operands(buf) {
				if v != nil && *v != nil {
					if g, ok := (*v).(*ssa.Function); ok && a.isCore(g) {
						hit(g, nil)
						a.innerCore(g, seen, hit)
					}
				}
			}
		}
	}
	for _, anon := range fn.AnonFuncs {
		a.innerCore(anon, seen, hit)
	}
}

// decryptPrimitive reports whether callee is one of the secret-value
// decryption primitives (listed verbatim in the markdown header).
func (a *analyzer) decryptPrimitive(callee *ssa.Function) bool {
	o := callee
	if callee.Origin() != nil {
		o = callee.Origin()
	}
	if o.Pkg == nil || o.Signature.Recv() == nil {
		return false
	}
	recv := types.TypeString(o.Signature.Recv().Type(), nil)
	switch {
	case o.Pkg.Pkg.Path() == encPkg && recv == "*"+encPkg+".Service" && strings.HasPrefix(o.Name(), "Decrypt"):
		return true
	case o.Pkg.Pkg.Path() == corePkg && o.Name() == "decryptVersionValue":
		return true
	}
	return false
}

// reachesDecrypt reports whether fn reaches a SECRET-VALUE read: the
// secret/version value decryption path ((*KeyorixCore).decryptVersionValue)
// or a federated connector read (ports.Connector/connect.Connector GetSecret).
func (a *analyzer) reachesDecrypt(fn *ssa.Function) bool {
	v, _ := a.decryptKinds(fn)
	return v
}

// decryptKinds returns (secretValueRead, anyDecrypt). anyDecrypt also counts
// server-internal decryption (MFA secrets, notification URLs, dynamic-secret
// admin credentials) through the same ports encryptor — the decrypt call alone
// cannot tell "returned to the caller" from "used internally", so that wider
// set is reported but does not by itself put an operation in scope.
func (a *analyzer) decryptKinds(fn *ssa.Function) (bool, bool) {
	if v, ok := a.decryptMemo[fn]; ok {
		return v, a.anyDecryptMemo[fn]
	}
	valueRead, anyDec := false, false
	a.innerCore(fn, map[*ssa.Function]bool{}, func(g *ssa.Function, c *ssa.CallCommon) {
		if g == nil {
			t := types.TypeString(c.Value.Type(), nil)
			// core reaches the encryptor only through a ports interface (ADR-109)
			if strings.HasPrefix(c.Method.Name(), "Decrypt") && strings.HasPrefix(t, portsPkg+".") {
				anyDec = true
				return
			}
			// federated read; core holds connectors as ports.Connector (ADR-109),
			// connect.Connector kept in case a path uses the concrete package's.
			if c.Method.Name() == "GetSecret" && (t == portsPkg+".Connector" || t == connectPkg+".Connector") {
				valueRead = true
			}
			return
		}
		if a.decryptPrimitive(g) {
			anyDec = true
			if g.Name() == "decryptVersionValue" {
				valueRead = true
			}
		}
	})
	a.decryptMemo[fn] = valueRead
	a.anyDecryptMemo[fn] = anyDec || valueRead
	return valueRead, anyDec || valueRead
}

// InnerReach returns the exported and unexported core functions fn reaches
// inside core, by name (used for guard calibration).
func (a *analyzer) innerNames(fn *ssa.Function) map[string]bool {
	if m, ok := a.innerMemo[fn]; ok {
		return m
	}
	m := map[string]bool{}
	a.innerCore(fn, map[*ssa.Function]bool{}, func(g *ssa.Function, _ *ssa.CallCommon) {
		if g != nil && a.isCore(g) {
			m[g.Name()] = true
		}
	})
	a.innerMemo[fn] = m
	return m
}

// ---------- rows ----------

// CoreRow is one exported core entry point reached by at least one in-population op.
type CoreRow struct {
	Core          string   `json:"core"`
	REST          []string `json:"rest"`
	GRPC          []string `json:"grpc"`
	Mutating      bool     `json:"mutating"`
	SecretReading bool     `json:"secret_reading"`
	ReachedBy     int      `json:"reached_by_all_ops"` // across the whole population, in or out
	Infra         bool     `json:"infra"`
	Guards        []string `json:"guards"`       // named guard functions reached inside core (display only)
	CoreRefusal   string   `json:"core_refusal"` // typed | untyped | typed+untyped | none (refusal.go)
}

// guardFuncs are the core authorization primitives whose presence in a core
// entry's inner reach is reported per row (for calibration and review).
var guardFuncs = []string{
	"requireGranterHoldsRolePermissions", "requireAdminAuthorityAt", "requireAccessRequestAuthorityAt",
	"RequireMachinePrivilegeCeiling", "Authorize", "CheckPermission", "guardLastProjectAdmin",
}

func (a *analyzer) buildRows(ops []*Op) []*CoreRow {
	reachedBy := map[string]int{}
	for _, op := range ops {
		for _, c := range op.CoreEntries {
			reachedBy[c]++
		}
	}
	// infrastructure threshold: a core method reached by >=10% of ALL
	// operations is a shared helper (auth/session/audit), not an operation.
	thr := len(ops) / 10
	rows := map[string]*CoreRow{}
	for _, op := range ops {
		if !op.Mutating && !op.SecretReading {
			continue
		}
		for _, c := range op.CoreEntries {
			r := rows[c]
			if r == nil {
				r = &CoreRow{Core: c, ReachedBy: reachedBy[c], Infra: reachedBy[c] >= thr}
				fn := a.coreMethod(c)
				if fn != nil {
					inner := a.innerNames(fn)
					for _, g := range guardFuncs {
						if inner[g] || c == g {
							r.Guards = append(r.Guards, g)
						}
					}
					r.SecretReading = a.reachesDecrypt(fn)
					rf := a.refusalOf(fn)
					switch {
					case rf.typed && rf.untyped:
						r.CoreRefusal = "typed+untyped"
					case rf.typed:
						r.CoreRefusal = "typed"
					case rf.untyped:
						r.CoreRefusal = "untyped"
					default:
						r.CoreRefusal = "none"
					}
				}
				rows[c] = r
			}
			if op.Mutating {
				r.Mutating = true
			}
			switch op.Layer {
			case "rest":
				r.REST = appendUniq(r.REST, strings.TrimPrefix(op.Key, "REST "))
			case "grpc":
				r.GRPC = appendUniq(r.GRPC, strings.TrimPrefix(op.Key, "GRPC "))
			}
		}
	}
	var out []*CoreRow
	for _, r := range rows {
		sort.Strings(r.REST)
		sort.Strings(r.GRPC)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Core < out[j].Core })
	return out
}

func appendUniq(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// ---------- helpers ----------

type pkgView struct {
	syntax []*ast.File
	info   *types.Info
}

func (a *analyzer) pkg(path string) *pkgView {
	v, ok := loadedSyntax[path]
	if !ok || v.info == nil {
		fatalf("package %s not loaded with syntax", path)
	}
	return v
}

// loadedSyntax is filled from the packages.Load graph (same Fset and
// types.Info objects the SSA program was built from).
var loadedSyntax = map[string]*pkgView{}

func (a *analyzer) typesPkg(path string) *types.Package {
	for _, p := range a.prog.AllPackages() {
		if p.Pkg.Path() == path {
			return p.Pkg
		}
	}
	fatalf("types package %s not found", path)
	return nil
}

func lookupNamed(prog *ssa.Program, pkgPath, name string) *types.Named {
	for _, p := range prog.AllPackages() {
		if p.Pkg.Path() == pkgPath {
			if tn, ok := p.Pkg.Scope().Lookup(name).(*types.TypeName); ok {
				return tn.Type().(*types.Named)
			}
		}
	}
	fatalf("%s.%s not found", pkgPath, name)
	return nil
}

func readKnownOperations(path string) map[string]bool {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	must(err)
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if bl, ok := kv.Key.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				out[normKey(strings.Trim(bl.Value, "\""))] = true
			}
		}
		return true
	})
	if len(out) == 0 {
		fatalf("no knownOperations keys read from %s", path)
	}
	return out
}

// normKey strips a trailing "/" from a REST key's path (not from "/").
func normKey(k string) string {
	if strings.HasPrefix(k, "REST ") && strings.HasSuffix(k, "/") && !strings.HasSuffix(k, " /") {
		return strings.TrimSuffix(k, "/")
	}
	return k
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "authzmatrix: "+f+"\n", a...)
	os.Exit(1)
}
