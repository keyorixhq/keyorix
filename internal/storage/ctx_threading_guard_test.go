// ctx_threading_guard_test.go — INV-STORAGE-32's structural guard: every storage
// method threads the caller's context.Context, so the per-statement SET LOCAL
// that ADR-103's Postgres RLS layer needs can ever reach the right tenant.
//
// WHAT IT CHECKS. Two rules, over two populations:
//
//	(a) FIRST-PARAM: every method of the storage.Storage interface (the interface
//	    files in internal/core/storage, embedded *Store interfaces followed) and
//	    every exported *LocalStorage method (internal/storage/store) has a leading
//	    `ctx context.Context` parameter that is named (not `_`, not unnamed in an
//	    implementation).
//	(b) NO SUBSTITUTION: no exported *LocalStorage method reaches a function that
//	    calls context.Background() / context.TODO(), directly or through
//	    same-package helpers. A root context minted below an exported method is a
//	    context the caller's tenant cannot ride on. Documented background-job entry
//	    points (backgroundEntryPoints) are exempt: they own a detached lifetime by
//	    design and never serve a caller's request.
//
// EVERY existing violation sits in testdata/ctx_threading_allowlist.d/ with an
// owner and a one-line reason; a row whose violation is gone fails
// TestCtxThreading_NoStaleAllowlistRows, like besteffort_callsite_guard_test.go.
//
// HOW (b) RESOLVES CALLS, and what it does NOT see (stated because "what does it
// silently skip, and does it say so?" is the question a guard must answer):
//
//   - Edges: `f(...)` for a package-level f declared in internal/storage/store,
//     and `r.f(...)` where r is the enclosing function's own receiver. NOT
//     followed: multi-hop selectors (ls.x.f), method values, calls through func
//     variables or struct fields, interface calls, and calls into other packages.
//   - Callees resolve by BARE NAME: two declarations sharing a name are one node,
//     so a hit can name a same-named sibling (over-approximation, never a miss).
//   - A call inside a func literal counts as a call of the enclosing function
//     (a goroutine started by an exported method is still that method's effect).
//   - "On a path that reaches a DB call" is NOT modelled: the whole store package
//     is database code, so every root-context site below an exported method is
//     reported and a reviewed exception goes in the allowlist with its reason.
//   - context imported under another name, and `context.WithoutCancel(ctx)` (a
//     deliberate detach that KEEPS the caller's values, so tenancy survives), are
//     not flagged.
//   - Only non-test, non-generated *.go files directly under the two directories.
//   - ctx-first is checked by type and name, not by use: a method that accepts
//     ctx and never reads it is not detected.
//
// Proof it can go red: TestCtxThreading_ScannerFixture scans testdata/ctxguard
// (one violating method of each kind, plus safe forms) on every run, so the guard
// cannot pass merely because it finds nothing. Production code is never edited.
package storage

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

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const (
	ctxGuardIfaceDir = "internal/core/storage"
	ctxGuardStoreDir = "internal/storage/store"
	ctxGuardAllowDir = "testdata/ctx_threading_allowlist.d"
	ctxGuardFixture  = "testdata/ctxguard"
)

// backgroundEntryPoints are the documented functions that mint a root context on
// purpose: detached background jobs registered in background_job_registry.go.
// TestCtxThreading_BackgroundEntryPointsExist fails if one is renamed or stops
// minting a root context, so the exemption cannot go stale silently.
var backgroundEntryPoints = map[string]string{
	"newBackgroundJob": "registers a detached background job and returns the context its goroutine runs under (INV-STORAGE-background-job-lifetime)",
}

// Floors under which a green result means the scanner broke. Values at time of
// writing are in the comment; floors sit well under them.
const (
	ctxGuardMinIfaceMethods = 300 // 479
	ctxGuardMinStoreMethods = 300 // 498
	ctxGuardMinRootSites    = 3   // 6
)

type ctxMethod struct {
	owner string // interface name or "LocalStorage"
	name  string
	ok    bool // leading named context.Context
}

type ctxScan struct {
	iface      []ctxMethod
	store      []ctxMethod
	rootFuncs  map[string]bool     // bare name -> body mints context.Background()/TODO()
	edges      map[string][]string // bare name -> bare callees (store package)
	exported   []string            // exported *LocalStorage method names
	rootCalled int                 // number of root-context call sites seen
}

// violations returns the sorted, de-duplicated violation keys.
func (s *ctxScan) violations() []string {
	set := map[string]bool{}
	for _, m := range s.iface {
		if !m.ok {
			set["iface:"+m.owner+"."+m.name+":first-param"] = true
		}
	}
	for _, m := range s.store {
		if !m.ok {
			set["store:"+m.name+":first-param"] = true
		}
	}
	for _, name := range s.exported {
		seen := map[string]bool{name: true}
		queue := []string{name}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if s.rootFuncs[cur] {
				if _, exempt := backgroundEntryPoints[cur]; !exempt {
					set["store:"+name+":reaches-root-ctx:"+cur] = true
				}
				continue
			}
			for _, c := range s.edges[cur] {
				if !seen[c] {
					seen[c] = true
					queue = append(queue, c)
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ctxParseDir(t *testing.T, fset *token.FileSet, paths []string) []*ast.File {
	t.Helper()
	var files []*ast.File
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("ctx-threading guard: parse %s: %v", p, err)
		}
		files = append(files, f)
	}
	return files
}

// ctxGoFiles lists the non-test, non-generated Go sources directly in dir (a
// real directory or a fixture: fixture sources are *.go.txt, mapped via ext).
// dir-listing-ok: two fixed storage directories, not a repo walk
func ctxGoFiles(t *testing.T, dir, ext string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ctx-threading guard: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ext) || strings.HasSuffix(n, "_test"+ext) || strings.Contains(n, "generated") {
			continue
		}
		out = append(out, filepath.Join(dir, n))
	}
	sort.Strings(out)
	return out
}

// ctxFirstParamOK: the first parameter is `<name> context.Context` with a usable
// name. In an interface an unnamed parameter is fine (named: false); in an
// implementation it is not, because an unnamed or `_` ctx cannot be threaded.
func ctxFirstParamOK(ft *ast.FuncType, requireName bool) bool {
	if ft.Params == nil || len(ft.Params.List) == 0 {
		return false
	}
	p := ft.Params.List[0]
	sel, ok := p.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Context" {
		return false
	}
	if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "context" {
		return false
	}
	if !requireName {
		return true
	}
	return len(p.Names) > 0 && p.Names[0].Name != "_"
}

func ctxRecvType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	e := fd.Recv.List[0].Type
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func ctxRecvName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
		return fd.Recv.List[0].Names[0].Name
	}
	return ""
}

// ctxInterfaceMethods collects the methods of root and, recursively, the local
// interfaces it embeds.
func ctxInterfaceMethods(files []*ast.File, root string) []ctxMethod {
	ifaces := map[string]*ast.InterfaceType{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				if ts, ok := sp.(*ast.TypeSpec); ok {
					if it, ok := ts.Type.(*ast.InterfaceType); ok {
						ifaces[ts.Name.Name] = it
					}
				}
			}
		}
	}
	var out []ctxMethod
	seen := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		it := ifaces[name]
		if it == nil {
			return
		}
		for _, fld := range it.Methods.List {
			switch ft := fld.Type.(type) {
			case *ast.FuncType:
				for _, n := range fld.Names {
					out = append(out, ctxMethod{owner: name, name: n.Name, ok: ctxFirstParamOK(ft, false)})
				}
			case *ast.Ident: // embedded local interface
				walk(ft.Name)
			}
		}
	}
	walk(root)
	return out
}

// ctxScanDirs scans the interface files and the store files. ifaceRoot is the
// interface to expand; implType the receiver type whose exported methods count.
func ctxScanDirs(t *testing.T, ifacePaths, storePaths []string, ifaceRoot, implType string) *ctxScan {
	t.Helper()
	fset := token.NewFileSet()
	s := &ctxScan{rootFuncs: map[string]bool{}, edges: map[string][]string{}}

	s.iface = ctxInterfaceMethods(ctxParseDir(t, fset, ifacePaths), ifaceRoot)

	files := ctxParseDir(t, fset, storePaths)
	declared := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				declared[fd.Name.Name] = true
			}
		}
	}
	exported := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if ctxRecvType(fd) == implType && ast.IsExported(name) {
				s.store = append(s.store, ctxMethod{owner: implType, name: name, ok: ctxFirstParamOK(fd.Type, true)})
				exported[name] = true
			}
			recv := ctxRecvName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if declared[fn.Name] {
						s.edges[name] = append(s.edges[name], fn.Name)
					}
				case *ast.SelectorExpr:
					x, isIdent := fn.X.(*ast.Ident)
					switch {
					case isIdent && x.Name == "context" && (fn.Sel.Name == "Background" || fn.Sel.Name == "TODO"):
						s.rootFuncs[name] = true
						s.rootCalled++
					case isIdent && recv != "" && x.Name == recv && declared[fn.Sel.Name]:
						s.edges[name] = append(s.edges[name], fn.Sel.Name)
					}
				}
				return true
			})
		}
	}
	for n := range exported {
		s.exported = append(s.exported, n)
	}
	sort.Strings(s.exported)
	return s
}

func ctxScanRepo(t *testing.T) *ctxScan {
	t.Helper()
	root := srcpath.RepoRoot()
	return ctxScanDirs(t,
		ctxGoFiles(t, filepath.Join(root, ctxGuardIfaceDir), ".go"),
		ctxGoFiles(t, filepath.Join(root, ctxGuardStoreDir), ".go"),
		"Storage", "LocalStorage")
}

type ctxAllowRow struct{ owner, reason string }

func ctxLoadAllowlist(t *testing.T) map[string]ctxAllowRow {
	t.Helper()
	entries, err := os.ReadDir(ctxGuardAllowDir)
	if err != nil {
		t.Fatalf("ctx-threading guard: %v", err)
	}
	rows := map[string]ctxAllowRow{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tsv") {
			continue
		}
		path := filepath.Join(ctxGuardAllowDir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ctx-threading guard: %v", err)
		}
		var cols []string
		for line := range strings.SplitSeq(string(b), "\n") {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if cols != nil {
				t.Fatalf("%s: want exactly one row per file", path)
			}
			cols = strings.Split(line, "\t")
			if len(cols) != 3 || strings.TrimSpace(cols[0]) == "" || strings.TrimSpace(cols[1]) == "" || strings.TrimSpace(cols[2]) == "" {
				t.Fatalf("%s: want 3 non-empty tab-separated columns (key, owning issue, reason), got %q", path, line)
			}
		}
		if cols == nil {
			t.Fatalf("%s: no row", path)
		}
		if want := strings.ReplaceAll(cols[0], ":", "__") + ".tsv"; e.Name() != want {
			t.Fatalf("%s: file name must match its key; want %s", path, want)
		}
		if _, dup := rows[cols[0]]; dup {
			t.Fatalf("%s: duplicate key %q", path, cols[0])
		}
		rows[cols[0]] = ctxAllowRow{owner: cols[1], reason: cols[2]}
	}
	return rows
}

// TestCtxThreading_EveryStorageMethodThreadsContext is the guard proper
// (INV-STORAGE-32).
func TestCtxThreading_EveryStorageMethodThreadsContext(t *testing.T) {
	s := ctxScanRepo(t)
	allow := ctxLoadAllowlist(t)
	var bad []string
	for _, k := range s.violations() {
		if _, ok := allow[k]; !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("INV-STORAGE-32: %d storage method(s) do not thread the caller's context. Every method of "+
			"storage.Storage / *LocalStorage must take a named leading `ctx context.Context`, and no exported method "+
			"may reach context.Background()/TODO() (ADR-103's per-statement SET LOCAL needs the caller's ctx). "+
			"Fix the method, or add a row (key, owning issue, reason) to internal/storage/%s:\n  %s",
			len(bad), ctxGuardAllowDir, strings.Join(bad, "\n  "))
	}
}

// TestCtxThreading_NoStaleAllowlistRows: a row that pardons nothing reads like a
// load-bearing one and silently pre-approves the shape coming back.
func TestCtxThreading_NoStaleAllowlistRows(t *testing.T) {
	s := ctxScanRepo(t)
	live := map[string]bool{}
	for _, k := range s.violations() {
		live[k] = true
	}
	var stale []string
	for k := range ctxLoadAllowlist(t) {
		if !live[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("INV-STORAGE-32: allowlist row(s) match no current violation; delete them from %s:\n  %s",
			ctxGuardAllowDir, strings.Join(stale, "\n  "))
	}
}

// TestCtxThreading_BackgroundEntryPointsExist: the exemption names functions; a
// renamed or changed one must fail here instead of exempting nothing.
func TestCtxThreading_BackgroundEntryPointsExist(t *testing.T) {
	s := ctxScanRepo(t)
	for name := range backgroundEntryPoints {
		if !s.rootFuncs[name] {
			t.Errorf("background entry point %q no longer exists or no longer mints a root context: update backgroundEntryPoints", name)
		}
	}
}

// TestCtxThreading_ScanPreconditionHolds: green results above are vacuous when
// the scan finds nothing, so guard the population, not just the verdict.
func TestCtxThreading_ScanPreconditionHolds(t *testing.T) {
	s := ctxScanRepo(t)
	t.Logf("scanned %d interface method(s), %d exported *LocalStorage method(s), %d root-context site(s)", len(s.iface), len(s.store), s.rootCalled)
	if len(s.iface) < ctxGuardMinIfaceMethods {
		t.Errorf("only %d storage.Storage method(s) found, floor %d: the interface walk stopped matching", len(s.iface), ctxGuardMinIfaceMethods)
	}
	if len(s.store) < ctxGuardMinStoreMethods {
		t.Errorf("only %d exported *LocalStorage method(s) found, floor %d: the receiver matcher stopped matching", len(s.store), ctxGuardMinStoreMethods)
	}
	if s.rootCalled < ctxGuardMinRootSites {
		t.Errorf("only %d context.Background()/TODO() site(s) found, floor %d: the root-context matcher stopped matching", s.rootCalled, ctxGuardMinRootSites)
	}
}

// TestCtxThreading_ScannerFixture plants one violation of each kind and the safe
// forms in testdata/ctxguard (*.go.txt, never compiled), so the guard is proven
// to go red and green independent of the repository's contents.
func TestCtxThreading_ScannerFixture(t *testing.T) {
	s := ctxScanDirs(t,
		ctxGoFiles(t, ctxGuardFixture, ".go.txt")[:1],
		ctxGoFiles(t, ctxGuardFixture, ".go.txt")[1:],
		"Storage", "LocalStorage")
	got := map[string]bool{}
	for _, k := range s.violations() {
		got[k] = true
	}
	want := []string{
		"iface:WidgetStore.DeleteWidget:first-param",
		"store:DeleteWidget:first-param",
		"store:DiscardsCtx:first-param",
		"store:UnnamedCtx:first-param",
		"store:SubstitutesDirect:reaches-root-ctx:SubstitutesDirect",
		"store:SubstitutesViaHelper:reaches-root-ctx:mintsTodo",
		"store:SubstitutesTwoHops:reaches-root-ctx:mintsTodo",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("fixture violation %s not reported (guard cannot go red); got %v", w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected exactly %d fixture violations, got %d: %v", len(want), len(got), got)
	}
	for k := range got {
		for _, safe := range []string{"GetWidget", "ThreadsCtx", "StartBackgroundThing", "UsesBackgroundJob", "WithoutCancelKeepsValues"} {
			if strings.Contains(k, ":"+safe+":") || strings.HasSuffix(k, "."+safe+":first-param") {
				t.Errorf("fixture safe form %s was reported (guard cannot go green): %s", safe, k)
			}
		}
	}
	if fmt.Sprint(s.exported) == "[]" {
		t.Error("fixture scan found no exported methods")
	}
}
