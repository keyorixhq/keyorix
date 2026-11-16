package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// tree is the content of the files authzgate reads at one revision.
type tree map[string][]byte

// readTree reads the files under dirs at rev with one `git archive`, so a plan
// over a historical merge needs no checkout.
func readTree(rev string, dirs ...string) (tree, error) {
	args := append([]string{"archive", "--format=tar", rev, "--"}, dirs...)
	out, err := git(args...)
	if err != nil {
		return nil, fmt.Errorf("git archive %s: %w", rev, err)
	}
	t := tree{}
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return t, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		t[h.Name] = b
	}
}

// git runs a git command at the top of the work tree: paths and pathspecs
// are repository-relative whatever the caller's directory (a test runs in its
// package directory).
func git(args ...string) ([]byte, error) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	cmd := exec.Command("git", args...) // #nosec G204 -- CI-only tool: fixed binary, no shell; args are revisions and repo paths from its own flags
	cmd.Dir = strings.TrimSpace(string(top))
	return cmd.Output()
}

// treeDirs are the paths a plan reads: the indexed product code, the RBAC
// seed migrations and the authzdiff op table.
var treeDirs = []string{"internal", "server", "pkg", "cmd", "migrations"}

// inScope reports whether a root-module Go file is product code the index
// covers. Excluded: test files, the separate modules (cli, operator, migrate)
// and tooling trees (not under treeDirs at all), the oracle itself
// (server/authzdiff: its changes are a FULL trigger of their own), generated
// protobuf code, the embedded web UI, testdata, and the test-support packages
// whose code only tests link (internal/testhelper, internal/testutil,
// internal/faultstorage: a generated wrapper that delegates every storage
// method and would otherwise reference every root; internal/core/storage/
// storagetest: the storage mocks).
func inScope(p string) bool {
	if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
		return false
	}
	if !slices.ContainsFunc(treeDirs, func(d string) bool { return strings.HasPrefix(p, d+"/") }) {
		return false
	}
	for _, x := range []string{"server/authzdiff/", "server/proto/", "server/webui/"} {
		if strings.HasPrefix(p, x) {
			return false
		}
	}
	return !slices.ContainsFunc(strings.Split(path.Dir(p), "/"), func(seg string) bool { return testSupportDirs[seg] })
}

// testSupportDirs are directory names of code only tests link: test helpers,
// storage mocks, the generated fault-injection wrapper, test inputs.
var testSupportDirs = map[string]bool{"testutil": true, "testhelper": true, "storagetest": true, "faultstorage": true, "testdata": true}

type declKind int

const (
	kindFunc declKind = iota
	kindVar
	kindConst
	kindType
)

// decl is one top-level declaration: a func or method, or one name of a
// const/var/type spec.
type decl struct {
	file       string
	pkg        string // directory of file
	name       string
	recv       string // receiver type name for a method
	start, end int    // line range, inclusive
	refs       map[string]bool
	strs       map[string]bool
	kind       declKind
	isConst    bool
}

// key is the name under which d is found: an exported name is global (any
// package may reference it), an unexported one exists only in its package.
func (d *decl) key() string { return keyOf(d.pkg, d.name) }

// keyOf resolves a reference to name made from package directory pkg.
func keyOf(pkg, name string) string {
	if ast.IsExported(name) {
		return name
	}
	return pkg + ":" + name
}

// index is every in-scope declaration, by key. Exported names are not
// qualified by package or receiver: a reference `x.Authorize` matches every
// declaration named Authorize. That over-approximates (more triggers), never
// under. Unexported names match only inside their own package, as in Go.
type index struct {
	decls  []*decl
	byKey  map[string][]*decl
	byFile map[string][]*decl
}

func newIndex() *index {
	return &index{byKey: map[string][]*decl{}, byFile: map[string][]*decl{}}
}

func (ix *index) add(d *decl) {
	ix.decls = append(ix.decls, d)
	ix.byKey[d.key()] = append(ix.byKey[d.key()], d)
	ix.byFile[d.file] = append(ix.byFile[d.file], d)
}

// parseDecls returns the top-level declarations of one Go file. A file that
// does not parse is an error: the plan must not silently skip code.
func parseDecls(file string, src []byte) ([]*decl, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []*decl
	mk := func(name string, n ast.Node, self *ast.Ident) *decl {
		d := &decl{
			file: file, pkg: path.Dir(file), name: name,
			start: fset.Position(n.Pos()).Line, end: fset.Position(n.End()).Line,
			refs: map[string]bool{}, strs: map[string]bool{},
		}
		ast.Inspect(n, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.Ident:
				if v != self {
					d.refs[v.Name] = true
				}
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					if s, err := strconv.Unquote(v.Value); err == nil {
						d.strs[s] = true
					}
				}
			}
			return true
		})
		return d
	}
	for _, gd := range f.Decls {
		switch g := gd.(type) {
		case *ast.FuncDecl:
			d := mk(g.Name.Name, g, g.Name)
			if g.Recv != nil && len(g.Recv.List) == 1 {
				d.recv = recvType(g.Recv.List[0].Type)
			}
			d.kind = kindFunc
			out = append(out, d)
		case *ast.GenDecl:
			for _, sp := range g.Specs {
				switch s := sp.(type) {
				case *ast.ValueSpec:
					for _, id := range s.Names {
						d := mk(id.Name, s, id)
						d.isConst = g.Tok == token.CONST
						d.kind = kindVar
						if d.isConst {
							d.kind = kindConst
						}
						// a grouped spec's doc/comment lines belong to it; take
						// the whole GenDecl range when it holds a single spec.
						if len(g.Specs) == 1 {
							d.start, d.end = fset.Position(g.Pos()).Line, fset.Position(g.End()).Line
						}
						out = append(out, d)
					}
				case *ast.TypeSpec:
					d := mk(s.Name.Name, s, s.Name)
					d.kind = kindType
					if len(g.Specs) == 1 {
						d.start, d.end = fset.Position(g.Pos()).Line, fset.Position(g.End()).Line
					}
					out = append(out, d)
				}
			}
		}
	}
	return out, nil
}

func recvType(t ast.Expr) string {
	for {
		switch v := t.(type) {
		case *ast.StarExpr:
			t = v.X
		case *ast.IndexExpr:
			t = v.X
		case *ast.IndexListExpr:
			t = v.X
		case *ast.Ident:
			return v.Name
		default:
			return ""
		}
	}
}

func buildIndex(t tree) (*index, error) {
	ix := newIndex()
	for _, p := range sortedKeys(t) {
		if !inScope(p) {
			continue
		}
		ds, err := parseDecls(p, t[p])
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			ix.add(d)
		}
	}
	return ix, nil
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// ---------- roots ----------

// coreDecisionRoots are the functions in internal/core that make a
// permission decision: every RBAC verdict is computed by one of them
// (Authorize and AuthorizePrincipal resolve through the storage roots below),
// plus the PAT restriction and the admin-role bypass list they consult.
// TestCoreDecisionRootsExist fails when one is renamed or removed.
var coreDecisionRoots = []string{
	"Authorize",
	"AuthorizePrincipal",
	"userHasScopedPermission",
	"principalHasScopedPermission",
	"patRestrictionFromContext",
	"isAdminRoleName",
	"adminRoleNames",
	"IsGlobalAdmin",
}

// storageRootFacets are the storage interfaces whose every method reads or
// writes RBAC state (internal/core/storage). Every other *Store facet
// contributes the methods whose name matches storageRootName.
var storageRootFacets = map[string]bool{"RBACStore": true, "UserRoleReads": true, "MachineRoleReads": true}

// storageRootName: role and permission resolution, group and project
// membership, secret ACLs and shares, the admin-bypass role set. Not "Grant"
// alone (MFA step-up and connect-ref grants are not RBAC) and not "Admin"
// alone (admin DSNs).
var storageRootName = regexp.MustCompile(`Role|Permission|ACL|Acl|Share|Member|AdminBypass`)

const storageIfaceDir = "internal/core/storage/"

// storageRoots derives, from the interface declarations in
// internal/core/storage (non-test files directly in that directory), the
// storage methods that carry authorization state.
func storageRoots(t tree) ([]string, error) {
	var out []string
	for _, p := range sortedKeys(t) {
		if !strings.HasPrefix(p, storageIfaceDir) || strings.Contains(p[len(storageIfaceDir):], "/") || !inScope(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, t[p], parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, gd := range f.Decls {
			g, ok := gd.(*ast.GenDecl)
			if !ok || g.Tok != token.TYPE {
				continue
			}
			for _, sp := range g.Specs {
				ts := sp.(*ast.TypeSpec)
				it, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}
				whole := storageRootFacets[ts.Name.Name]
				for _, m := range it.Methods.List {
					for _, n := range m.Names {
						if whole || storageRootName.MatchString(n.Name) {
							out = append(out, n.Name)
						}
					}
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// ---------- permission universe ----------

var seedPermName = regexp.MustCompile(`'([a-z_]+\.[a-z_]+)'`)

// permUniverse is every permission name the product knows: the quoted names
// in the RBAC seed migrations (migrations/*.up.sql that mention
// permissions), and the values of the perm* string constants in the index.
func permUniverse(t tree, ix *index) map[string]bool {
	u := map[string]bool{}
	for _, p := range sortedKeys(t) {
		if !isRBACMigration(p, t[p]) {
			continue
		}
		for _, m := range seedPermName.FindAllSubmatch(t[p], -1) {
			u[string(m[1])] = true
		}
	}
	for _, d := range ix.decls {
		if d.isConst && isPermConstName(d.name) {
			for s := range d.strs {
				u[s] = true
			}
		}
	}
	return u
}

func isRBACMigration(p string, b []byte) bool {
	return strings.HasPrefix(p, "migrations/") && path.Ext(p) == ".sql" &&
		bytes.Contains(bytes.ToLower(b), []byte("permission"))
}

var permConstName = regexp.MustCompile(`^[pP]erm[A-Z]`)

func isPermConstName(n string) bool { return permConstName.MatchString(n) }

// ---------- closures ----------

// maxNameDecls: a key declared more often than this in the index is
// ambiguous: a reference to it says nothing about which declaration it
// reaches, so the closure does not propagate through it (see blocked).
const maxNameDecls = 4

// commonNames are method names that library types also declare (error,
// fmt.Stringer, io, http, sql, context): a selector with one of these names
// is far more often a library call than a call of the in-repo declaration.
var commonNames = map[string]bool{
	"Error": true, "String": true, "Is": true, "As": true, "Unwrap": true, "Close": true,
	"Read": true, "Write": true, "Get": true, "Set": true, "Add": true, "Del": true,
	"Delete": true, "Len": true, "Less": true, "Swap": true, "Scan": true, "Value": true,
	"Err": true, "Done": true, "Run": true, "Start": true, "Stop": true, "Wait": true,
	"Name": true, "Type": true, "New": true, "Load": true, "Store": true, "Validate": true,
	"Enabled": true, "ServeHTTP": true, "Lock": true, "Unlock": true, "Next": true,
	"Open": true, "Ping": true, "Reset": true, "Allow": true, "Check": true, "Do": true,
	"MarshalJSON": true, "UnmarshalJSON": true, "Init": true, "Update": true, "Create": true, "List": true,
}

// coreDir is the package of coreDecisionRoots.
const coreDir = "internal/core"

// model is the derived trigger set over one index. Every set is keyed by
// decl.key / keyOf.
type model struct {
	ix       *index
	roots    map[string]bool // decision roots: core + storage
	perms    map[string]bool // permission universe (names, not keys)
	permDefs map[string]bool // constants that define a permission
	rows     map[string]bool // authzdiff matrix rows (exported core method names)
	helpers  map[string]bool // keys the closure propagates through
	why      map[*decl]string
}

func newModel(t tree) (*model, error) {
	ix, err := buildIndex(t)
	if err != nil {
		return nil, err
	}
	sr, err := storageRoots(t)
	if err != nil {
		return nil, err
	}
	rows, err := matrixRows(t)
	if err != nil {
		return nil, err
	}
	m := &model{ix: ix, roots: map[string]bool{}, permDefs: map[string]bool{}, rows: rows, helpers: map[string]bool{}, why: map[*decl]string{}}
	for _, r := range coreDecisionRoots {
		m.roots[keyOf(coreDir, r)] = true
	}
	for _, r := range sr {
		m.roots[r] = true // interface methods: exported
	}
	m.perms = permUniverse(t, ix)
	for _, d := range ix.decls {
		if d.isConst && (isPermConstName(d.name) || m.hasPermLiteral(d)) {
			m.permDefs[d.key()] = true
		}
	}
	m.close()
	return m, nil
}

func (m *model) hasPermLiteral(d *decl) bool {
	for s := range d.strs {
		if m.perms[s] {
			return true
		}
	}
	return false
}

// propagatable: the closure may follow references that resolve to key k
// (declared by d).
func (m *model) propagatable(d *decl) bool {
	return d.name != "_" && !commonNames[d.name] && len(m.ix.byKey[d.key()]) <= maxNameDecls
}

// carries: d is a declaration whose callers become permission-check code: a
// func or a var (a table of roles, a bypass list) with an unambiguous name.
// Not limited to check-shaped results (error, bool): isGlobalAdminRoleName
// answers (string, error) and gates LiftLegalHold.
func (m *model) carries(d *decl) bool {
	return (d.kind == kindFunc || d.kind == kindVar) && m.propagatable(d)
}

// isRoot: d declares a decision root. A transport declaration never does: a
// handler named like a storage method (RBACHandler.AssignRole) is not the
// RBAC store, it is judged by what it references.
func (m *model) isRoot(d *decl) bool {
	return m.roots[d.key()] && !strings.HasPrefix(d.file, "server/")
}

// directReason says why d is permission-check code without the closure, or "".
func (m *model) directReason(d *decl) string {
	switch {
	case m.isRoot(d):
		return "decision root"
	case m.permDefs[d.key()]:
		return "defines a permission constant"
	case m.hasPermLiteral(d):
		return "names a permission"
	}
	for _, r := range sortedKeys(d.refs) {
		k := keyOf(d.pkg, r)
		if m.roots[k] {
			return "calls decision root " + r
		}
		if m.permDefs[k] {
			return "uses permission constant " + r
		}
	}
	return ""
}

// close computes the trigger set: the declarations that make a permission
// decision, define or name a permission, reference one that does, call a
// helper that (transitively) does, or are transport code that calls an
// authzdiff row whose core method is in the set.
func (m *model) close() {
	for r := range m.roots {
		m.helpers[r] = true
	}
	for p := range m.permDefs {
		m.helpers[p] = true
	}
	mark := func(d *decl, why string) bool {
		m.why[d] = why
		if m.carries(d) && !m.helpers[d.key()] {
			m.helpers[d.key()] = true
			return true
		}
		return false
	}
	for _, d := range m.ix.decls {
		if r := m.directReason(d); r != "" {
			mark(d, r)
		}
	}
	for changed := true; changed; {
		changed = false
		for _, d := range m.ix.decls {
			if m.why[d] != "" {
				continue
			}
			if r := m.reachedHelper(d); r != "" {
				changed = mark(d, "reaches "+r) || changed
			}
		}
	}
	// Rows: a core row method in the set makes its transport callers
	// (server/**) permission-check code: the IssueMachineToken and role-assign
	// handlers and every other route the oracle compares.
	relRows := map[string]bool{}
	for _, d := range m.ix.decls {
		if m.why[d] != "" && d.recv == "KeyorixCore" && m.rows[d.name] {
			relRows[d.name] = true
		}
	}
	for _, d := range m.ix.decls {
		if m.why[d] != "" || !strings.HasPrefix(d.file, "server/") {
			continue
		}
		for _, r := range sortedKeys(d.refs) {
			if relRows[r] {
				m.why[d] = "calls authz-checked row " + r
				break
			}
		}
	}
}

func (m *model) reachedHelper(d *decl) string {
	for _, r := range sortedKeys(d.refs) {
		if m.helpers[keyOf(d.pkg, r)] {
			return r
		}
	}
	return ""
}

// reason is why d is permission-check code, or "" when it is not. A decl from
// another revision (the base side of a diff) is judged against this model.
func (m *model) reason(d *decl) string {
	if w, ok := m.why[d]; ok {
		return w
	}
	if r := m.directReason(d); r != "" {
		return r
	}
	if r := m.reachedHelper(d); r != "" {
		return "reaches " + r
	}
	return ""
}

// callers is the upward closure of changed declaration c: every declaration
// that references it, transitively, following only propagatable keys. The
// result holds bare names (an op names exported methods). Transport code
// (server/**: REST handlers, gRPC services, middleware, interceptors) is where
// the oracle enters, so a transport declaration joins the closure (its name
// can match an op's gRPC call) but is not followed further: above it is route
// registration and server start-up. blocked lists the non-transport
// declarations that reference the closure but cannot be followed (ambiguous
// or library-like name): a plan that meets one cannot trust a narrow op
// selection. With inServer (c is transport code) only server/** declarations
// are callers: nothing outside the transport calls a handler, and an exported
// handler name (GetSecret) also names unrelated clients elsewhere.
func (m *model) callers(c *decl, inServer bool) (up map[string]bool, blocked []string) {
	up = map[string]bool{c.name: true}
	src := map[string]bool{c.key(): true}
	seen := map[*decl]bool{}
	for changed := true; changed; {
		changed = false
		for _, d := range m.ix.decls {
			if seen[d] || d.kind == kindType || d.kind == kindConst {
				continue // a type or const mentioning it is not a caller
			}
			if inServer && !strings.HasPrefix(d.file, "server/") {
				continue
			}
			hit := false
			for r := range d.refs {
				if src[keyOf(d.pkg, r)] {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			seen[d] = true
			up[d.name] = true
			switch {
			case strings.HasPrefix(d.file, "server/"):
			case !m.propagatable(d):
				blocked = append(blocked, qual(d)+" in "+d.file)
			case !src[d.key()]:
				src[d.key()] = true
				changed = true
			}
		}
	}
	slices.Sort(blocked)
	return up, blocked
}

// matrixRows reads the core method names of server/authzdiff/matrix.json.
func matrixRows(t tree) (map[string]bool, error) {
	b, ok := t["server/authzdiff/matrix.json"]
	if !ok {
		return nil, fmt.Errorf("server/authzdiff/matrix.json not found")
	}
	var mx struct {
		Rows []struct {
			Core string `json:"core"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(b, &mx); err != nil {
		return nil, fmt.Errorf("matrix.json: %w", err)
	}
	rows := map[string]bool{}
	for _, r := range mx.Rows {
		if r.Core != "" {
			rows[r.Core] = true
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("matrix.json has no rows")
	}
	return rows, nil
}
