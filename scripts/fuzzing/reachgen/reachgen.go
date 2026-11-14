// Package reachgen is a reachability-first fuzz-harness lead generator.
//
// It answers a narrow, auditable question: "which exported functions of
// third-party modules does Keyorix code actually call, with arguments that can
// carry attacker- or operator-influenced data (request bodies, uploaded files,
// configuration, or backend responses)?" — and ranks those entry points by how
// often they are called and whether an existing Fuzz target already covers
// them. The top-ranked UNCOVERED entries are the leads worth a hand-written,
// red-proofed fuzz oracle.
//
// This is deliberately a lead generator, never a gate. The provenance analysis
// is a lightweight, intra-procedural, best-effort heuristic (see Classify and
// the WhatThisDoesNotDo note below). Its output is reviewed by a human before
// any harness is trusted, exactly like autofuzzgen.
//
// # What this does NOT do (read before trusting a row)
//
//   - It is intra-procedural with 1-level-plus-fixpoint local taint only. It
//     does NOT follow taint across function boundaries, so a value laundered
//     through a helper (func parse(b []byte) and the []byte came from a request)
//     is seen only at the helper's own call site, not at parse's internal call.
//     This UNDER-counts reachability; it never fabricates a request source.
//   - "Backend-response" and "config" provenance are recognised by a fixed list
//     of package-path prefixes and type-name shapes (see backendPrefixes,
//     configTypeHint). A driver not on that list is missed.
//   - It classifies by call SITE, not by a constructed runtime wiring. A call
//     site existing is NOT proof the path is reachable in a real deployment
//     (see CLAUDE.md "A Go call graph is not a deployment path"). The ranked
//     list is a starting point for that trace, not a substitute for it.
//   - Coverage ("is there already a Fuzz target") is matched by third-party
//     package import + function-name token appearing in a *_test.go that also
//     declares a FuzzXxx. It can mis-flag a target that imports a package for an
//     unrelated reason as "covered". Treated as a hint, re-checked by hand.
package reachgen

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Provenance labels the best-effort source of a call argument.
type Provenance string

const (
	ProvRequest Provenance = "request-body"      // a string/[]byte/io.Reader/*http.Request param reaches the arg
	ProvUpload  Provenance = "uploaded-file"     // a multipart.File / multipart.FileHeader reaches the arg
	ProvConfig  Provenance = "config"            // a config-typed value, os.Getenv, or internal/config value reaches the arg
	ProvBackend Provenance = "backend-response"  // a value returned by a DB/driver/cloud-backend call reaches the arg
	ProvStatic  Provenance = "static"            // nothing untrusted detected (literal/const/internal only)
)

// untrustedProv is the set of provenance labels that make a call site a fuzz lead.
func untrustedProv(p Provenance) bool {
	switch p {
	case ProvRequest, ProvUpload, ProvConfig, ProvBackend:
		return true
	}
	return false
}

// CallSite is a single call to a third-party exported function from Keyorix code.
type CallSite struct {
	Pkg  string // Keyorix package import path containing the call
	File string // file base name
	Line int
	Func string // enclosing function name (or "<init>"/"<unknown>")
	Prov []Provenance
}

func (c CallSite) Untrusted() bool {
	for _, p := range c.Prov {
		if untrustedProv(p) {
			return true
		}
	}
	return false
}

// Entry aggregates every call site of one third-party exported function.
type Entry struct {
	Module   string // best-effort module path (e.g. github.com/jackc/pgx/v5)
	Pkg      string // third-party package import path
	Func     string // exported func, or "Recv.Method" for a method
	Sites    []CallSite
	Covered  bool // an existing Fuzz target appears to cover this
	ProvAgg  map[Provenance]int
	Sig      string   // rendered signature (params only), best-effort
	Params   []string // param kind tokens: string/[]byte/io.Reader/struct/other
	Fuzzable bool     // every param is a kind a draft harness can synthesise
	IsMethod bool
}

// UntrustedSites counts call sites with at least one untrusted provenance label.
func (e Entry) UntrustedSites() int {
	n := 0
	for _, s := range e.Sites {
		if s.Untrusted() {
			n++
		}
	}
	return n
}

// Result is the full scan outcome.
type Result struct {
	Entries []Entry
	// LoadErrors carries non-fatal package load diagnostics (offline builds etc.).
	LoadErrors []string
}

// Config controls a scan.
type Config struct {
	ModulePrefix string   // the Keyorix module path; calls into packages under it are "own code", not third-party
	Patterns     []string // go/packages load patterns, e.g. []string{"./..."}
	Dir          string   // working directory for the load
	Env          []string // environment for the load (GOFLAGS/GOMODCACHE/... ); nil = inherit
	// Coverage lets the caller supply a pre-computed coverage predicate. If nil,
	// coverage is left false and the caller fills it in (see MarkCovered).
}

// backendPrefixes are import-path prefixes whose call return values are treated
// as "backend-response" provenance (an attacker-controlled upstream can shape them).
var backendPrefixes = []string{
	"database/sql",
	"github.com/jackc/pgx",
	"github.com/jackc/pgconn",
	"github.com/jackc/pgproto3",
	"github.com/go-sql-driver/mysql",
	"github.com/redis/go-redis",
	"github.com/aws/aws-sdk-go",
	"github.com/aws/smithy-go",
	"cloud.google.com/go",
	"github.com/Azure/azure-sdk-for-go",
	"github.com/hashicorp/vault",
	"github.com/hashicorp/vault/api",
	"go.mongodb.org/mongo-driver",
}

// configPrefixes are import-path prefixes whose values are treated as "config".
func (c *scanner) configPrefix(path string) bool {
	return strings.HasPrefix(path, c.cfg.ModulePrefix+"/internal/config") ||
		strings.HasPrefix(path, c.cfg.ModulePrefix+"/config")
}

func isBackendPath(path string) bool {
	for _, p := range backendPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// configTypeHint reports whether a named type looks like configuration.
func configTypeHint(name string) bool {
	for _, h := range []string{"Config", "Options", "Settings", "Opts"} {
		if strings.Contains(name, h) {
			return true
		}
	}
	return false
}

// isStdlib reports whether an import path is from the standard library (no dot
// in the first path segment).
func isStdlib(path string) bool {
	if path == "" {
		return true
	}
	seg := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		seg = path[:i]
	}
	return !strings.Contains(seg, ".")
}

// Scan loads the configured packages and returns ranked third-party entries.
func Scan(cfg Config) (*Result, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedImports |
		packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo |
		packages.NeedDeps | packages.NeedModule
	lcfg := &packages.Config{
		Mode: mode,
		Dir:  cfg.Dir,
		Env:  cfg.Env,
	}
	pkgs, err := packages.Load(lcfg, cfg.Patterns...)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	for _, p := range pkgs {
		for _, e := range p.Errors {
			res.LoadErrors = append(res.LoadErrors, e.Error())
		}
	}
	s := &scanner{cfg: cfg, entries: map[string]*Entry{}}
	for _, p := range pkgs {
		if p.Types == nil || p.TypesInfo == nil {
			continue
		}
		// Only scan Keyorix's own packages for call sites.
		if !strings.HasPrefix(p.PkgPath, cfg.ModulePrefix) {
			continue
		}
		s.scanPkg(p)
	}
	res.Entries = s.ranked()
	return res, nil
}

type scanner struct {
	cfg     Config
	entries map[string]*Entry
}

func (s *scanner) key(pkgPath, fn string) string { return pkgPath + "\x00" + fn }

func (s *scanner) scanPkg(p *packages.Package) {
	info := p.TypesInfo
	fset := p.Fset
	// Module lookup for imported packages.
	modOf := func(path string) string {
		if imp, ok := p.Imports[path]; ok && imp.Module != nil {
			return imp.Module.Path
		}
		return coarseModule(path)
	}
	for _, file := range p.Syntax {
		// Walk top-level declarations so we know the enclosing function.
		ast.Inspect(file, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			fn := funcName(fd)
			taint := s.buildTaint(info, fd)
			ast.Inspect(fd, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				obj := calleeObj(info, call.Fun)
				if obj == nil || obj.Pkg() == nil {
					return true
				}
				pkgPath := obj.Pkg().Path()
				if isStdlib(pkgPath) || strings.HasPrefix(pkgPath, s.cfg.ModulePrefix) {
					return true
				}
				if !obj.Exported() {
					return true
				}
				prov := s.argProvenance(info, taint, call)
				pos := fset.Position(call.Pos())
				cs := CallSite{
					Pkg:  p.PkgPath,
					File: baseName(pos.Filename),
					Line: pos.Line,
					Func: fn,
					Prov: prov,
				}
				fname := funcDisplayName(obj)
				k := s.key(pkgPath, fname)
				e := s.entries[k]
				if e == nil {
					sig, params, fuzzable, isMethod := signatureInfo(obj)
					e = &Entry{
						Module:   modOf(pkgPath),
						Pkg:      pkgPath,
						Func:     fname,
						ProvAgg:  map[Provenance]int{},
						Sig:      sig,
						Params:   params,
						Fuzzable: fuzzable,
						IsMethod: isMethod,
					}
					s.entries[k] = e
				}
				e.Sites = append(e.Sites, cs)
				for _, pr := range prov {
					e.ProvAgg[pr]++
				}
				return true
			})
			return false // do not descend into nested funcs twice; handled by inner Inspect
		})
	}
}

// taintSet maps a local var/param object to the provenance labels it carries.
type taintSet map[types.Object]map[Provenance]bool

func (s *scanner) buildTaint(info *types.Info, fd *ast.FuncDecl) taintSet {
	ts := taintSet{}
	add := func(o types.Object, p Provenance) {
		if o == nil {
			return
		}
		m := ts[o]
		if m == nil {
			m = map[Provenance]bool{}
			ts[o] = m
		}
		m[p] = true
	}
	// Seed from parameters by type.
	if fd.Type.Params != nil {
		for _, field := range fd.Type.Params.List {
			t := info.TypeOf(field.Type)
			lbl := untrustedTypeLabel(t)
			if lbl == "" {
				continue
			}
			for _, name := range field.Names {
				if o := info.Defs[name]; o != nil {
					add(o, lbl)
				}
			}
		}
	}
	// Fixpoint over assignments: propagate labels through local := / = .
	for range 4 {
		changed := false
		ast.Inspect(fd, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			// Compute union of rhs provenance.
			rhsProv := map[Provenance]bool{}
			for _, r := range as.Rhs {
				for p := range s.exprProvenance(info, ts, r) {
					rhsProv[p] = true
				}
			}
			if len(rhsProv) == 0 {
				return true
			}
			// Assign to each lhs ident.
			for _, l := range as.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				o := info.ObjectOf(id)
				if o == nil {
					continue
				}
				for p := range rhsProv {
					if ts[o] == nil || !ts[o][p] {
						add(o, p)
						changed = true
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
	return ts
}

// exprProvenance returns the provenance labels an expression carries, using the
// current taint set plus direct source detection (backend calls, config, etc.).
func (s *scanner) exprProvenance(info *types.Info, ts taintSet, e ast.Expr) map[Provenance]bool {
	out := map[Provenance]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			o := info.ObjectOf(x)
			if o == nil {
				return true
			}
			if v, ok := o.(*types.Var); ok && v.IsField() {
				return true // field selector; base ident handled separately
			}
			if m := ts[o]; m != nil {
				for p := range m {
					out[p] = true
				}
			}
			// Package-level config value?
			if o.Pkg() != nil && s.configPrefix(o.Pkg().Path()) {
				out[ProvConfig] = true
			}
			// A value whose named type looks like configuration (Config/Options/...).
			if ot := o.Type(); ot != nil {
				t := ot
				if ptr, ok := t.(*types.Pointer); ok {
					t = ptr.Elem()
				}
				if named, ok := t.(*types.Named); ok && named.Obj() != nil && configTypeHint(named.Obj().Name()) {
					out[ProvConfig] = true
				}
			}
		case *ast.CallExpr:
			if obj := calleeObj(info, x.Fun); obj != nil && obj.Pkg() != nil {
				path := obj.Pkg().Path()
				if isBackendPath(path) {
					out[ProvBackend] = true
				}
				if path == "os" && obj.Name() == "Getenv" {
					out[ProvConfig] = true
				}
				if s.configPrefix(path) {
					out[ProvConfig] = true
				}
			}
		}
		return true
	})
	// A config-typed value read anywhere in the expr.
	if t := info.TypeOf(e); t != nil {
		if named, ok := t.(*types.Named); ok && named.Obj() != nil && configTypeHint(named.Obj().Name()) {
			out[ProvConfig] = true
		}
	}
	return out
}

// argProvenance computes the provenance label set for a call's arguments.
func (s *scanner) argProvenance(info *types.Info, ts taintSet, call *ast.CallExpr) []Provenance {
	set := map[Provenance]bool{}
	for _, a := range call.Args {
		for p := range s.exprProvenance(info, ts, a) {
			set[p] = true
		}
	}
	if len(set) == 0 {
		return []Provenance{ProvStatic}
	}
	var out []Provenance
	for _, p := range []Provenance{ProvRequest, ProvUpload, ProvConfig, ProvBackend} {
		if set[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []Provenance{ProvStatic}
	}
	return out
}

// untrustedTypeLabel returns a provenance label if a parameter type is one that
// commonly carries attacker/operator input, else "".
func untrustedTypeLabel(t types.Type) Provenance {
	if t == nil {
		return ""
	}
	// Peel pointer.
	for {
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
			continue
		}
		break
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		if u.Kind() == types.String {
			return ProvRequest
		}
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Byte {
			return ProvRequest
		}
	case *types.Interface:
		// io.Reader / io.ReadCloser etc: interface with a Read method.
		for i := range u.NumMethods() {
			if u.Method(i).Name() == "Read" {
				return ProvRequest
			}
		}
	}
	// Named types: *http.Request, multipart.FileHeader/File.
	if named, ok := t.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
		p := named.Obj().Pkg().Path()
		n := named.Obj().Name()
		switch {
		case p == "net/http" && n == "Request":
			return ProvRequest
		case p == "mime/multipart" && (n == "FileHeader" || n == "File"):
			return ProvUpload
		}
	}
	return ""
}

// calleeObj resolves the function/method object a CallExpr invokes.
func calleeObj(info *types.Info, fun ast.Expr) types.Object {
	switch f := fun.(type) {
	case *ast.Ident:
		return info.ObjectOf(f)
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[f]; ok {
			return sel.Obj()
		}
		return info.ObjectOf(f.Sel)
	case *ast.IndexExpr: // generic instantiation f[T]()
		return calleeObj(info, f.X)
	case *ast.IndexListExpr:
		return calleeObj(info, f.X)
	case *ast.ParenExpr:
		return calleeObj(info, f.X)
	}
	return nil
}

// funcDisplayName renders "Func" or "Recv.Method" for a func object.
func funcDisplayName(obj types.Object) string {
	fn, ok := obj.(*types.Func)
	if !ok {
		return obj.Name()
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return fn.Name()
	}
	recv := sig.Recv().Type()
	for {
		if ptr, ok := recv.(*types.Pointer); ok {
			recv = ptr.Elem()
			continue
		}
		break
	}
	if named, ok := recv.(*types.Named); ok && named.Obj() != nil {
		return named.Obj().Name() + "." + fn.Name()
	}
	return fn.Name()
}

// signatureInfo renders a func object's parameter list and classifies whether a
// draft harness can synthesise every parameter from fuzz bytes.
func signatureInfo(obj types.Object) (sig string, params []string, fuzzable bool, isMethod bool) {
	fn, ok := obj.(*types.Func)
	if !ok {
		return "", nil, false, false
	}
	s, ok := fn.Type().(*types.Signature)
	if !ok {
		return "", nil, false, false
	}
	isMethod = s.Recv() != nil
	ps := s.Params()
	var parts []string
	allSimple := ps.Len() > 0
	for i := range ps.Len() {
		pt := ps.At(i).Type()
		kind := paramKind(pt)
		params = append(params, kind)
		switch kind {
		case "string", "[]byte", "io.Reader", "int", "bool":
			// synthesisable from fuzz bytes
		default:
			allSimple = false
		}
		parts = append(parts, types.TypeString(pt, func(p *types.Package) string { return p.Name() }))
	}
	fuzzable = allSimple
	sig = "(" + strings.Join(parts, ", ") + ")"
	return sig, params, fuzzable, isMethod
}

// paramKind classifies a parameter type for draft synthesis.
func paramKind(t types.Type) string {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch u.Kind() {
		case types.String:
			return "string"
		case types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
			types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64:
			return "int"
		case types.Bool:
			return "bool"
		}
		return "other"
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Byte {
			return "[]byte"
		}
		return "other"
	case *types.Interface:
		for i := range u.NumMethods() {
			if u.Method(i).Name() == "Read" {
				return "io.Reader"
			}
		}
		return "other"
	case *types.Struct:
		return "struct"
	case *types.Pointer:
		if _, ok := u.Elem().Underlying().(*types.Struct); ok {
			return "struct"
		}
		return "other"
	}
	return "other"
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Name == nil {
		return "<unknown>"
	}
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return "(recv)." + fd.Name.Name
	}
	return fd.Name.Name
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// coarseModule derives a module-ish prefix from an import path when real module
// info is unavailable.
func coarseModule(path string) string {
	parts := strings.Split(path, "/")
	switch {
	case len(parts) >= 3 && (parts[0] == "github.com" || parts[0] == "gitlab.com" || parts[0] == "bitbucket.org"):
		m := strings.Join(parts[:3], "/")
		// include a trailing /vN major-version element if present
		if len(parts) >= 4 && isMajorVersion(parts[3]) {
			m = m + "/" + parts[3]
		}
		return m
	case len(parts) >= 2 && parts[0] == "golang.org":
		return strings.Join(parts[:3], "/")
	case len(parts) >= 1 && strings.HasPrefix(parts[0], "gopkg.in"):
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
	}
	if len(parts) >= 2 {
		return strings.Join(parts[:2], "/")
	}
	return path
}

func isMajorVersion(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ranked returns entries sorted: untrusted entries first, then by untrusted
// site count desc, then total site count desc, then package+func for stability.
func (s *scanner) ranked() []Entry {
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].UntrustedSites(), out[j].UntrustedSites()
		if ai != aj {
			return ai > aj
		}
		if len(out[i].Sites) != len(out[j].Sites) {
			return len(out[i].Sites) > len(out[j].Sites)
		}
		if out[i].Pkg != out[j].Pkg {
			return out[i].Pkg < out[j].Pkg
		}
		return out[i].Func < out[j].Func
	})
	return out
}

// MarkCovered sets Covered on entries whose third-party package is imported by a
// *_test.go file that declares a FuzzXxx function AND whose function-name token
// appears there. coveredPkgFuncs maps pkgPath -> set of lower-cased tokens that
// appear near a Fuzz target. It is a hint, re-checked by hand.
func MarkCovered(entries []Entry, coveredPkgFuncs map[string]map[string]bool) {
	for i := range entries {
		toks := coveredPkgFuncs[entries[i].Pkg]
		if toks == nil {
			continue
		}
		base := baseFuncToken(entries[i].Func)
		if toks[strings.ToLower(base)] || toks["*"] {
			entries[i].Covered = true
		}
	}
}

func baseFuncToken(fn string) string {
	if i := strings.LastIndexByte(fn, '.'); i >= 0 {
		return fn[i+1:]
	}
	return fn
}

// Pos is a convenience for tests.
func Pos(fset *token.FileSet, p token.Pos) token.Position { return fset.Position(p) }
