// Command authzgate decides whether a pull request changes permission-check
// code and, if it does, which server/authzdiff operations the strict oracle
// sweep must run (the authz-oracle job in .github/workflows/ci.yml;
// AUTHZ-MODEL-GUARD-1, registry KFZ-2026-092). #4332 tightened
// IssueMachineToken with every check green; the oracle model was not updated
// and FuzzAuthzDiff reported the disagreement hours later on a fuzz lane. A
// strict sweep of machine.token.issue reports it in under a second.
//
//	authzgate plan -base REV [-head REV]  prints mode=none|ops|full and ops=a,b,...
//	authzgate inventory [-rev REV]         prints the trigger set, one declaration per line
//	authzgate check-log [-full] -ops a,b LOG  fails unless every planned op (with -full: exactly every op) ran
//
// The trigger set is derived by call shape, not by file name. Its roots are
// the permission-decision functions of internal/core (coreDecisionRoots), the
// storage methods that carry RBAC state (derived from the interfaces in
// internal/core/storage), and the permission constants and seed data (the
// perm* constants, the RBAC seed migrations). A top-level declaration is
// permission-check code when it references a root or a permission constant,
// names a permission, references a func or var that is permission-check code
// (a fixpoint), or is transport code (server/**) calling an authzdiff row
// whose core method is. A changed line inside such a declaration, on either
// side of the diff, triggers the gate. `authzgate inventory` lists the set.
//
// Mode ops runs only the authzdiff operations whose op literal names the
// changed declaration or one of its callers (and, for a handler, the rows it
// calls). Mode full runs the whole strict sweep, chosen when the narrow
// mapping cannot be trusted: a decision root, a permission constant or table,
// request-wide transport authorization (middleware, interceptors, router) or
// an RBAC migration changed; a relevant declaration was deleted; a caller has
// an ambiguous name the mapping cannot follow; the mapping selects most ops
// anyway; or server/authzdiff or this gate changed. A ci.yml change runs two
// canary ops, so the job's wiring is exercised without a full sweep.
//
// What it does not see, by construction:
//   - references are matched by name (exported names globally, unexported
//     names within their package), so a call through a function value whose
//     name is unrelated to the root (a field assigned from c.Authorize, then
//     called) is invisible. TestEveryRootReferenceIsInTheTriggerSet
//     type-checks internal/core and server and fails on exactly that shape.
//   - names declared more than maxNameDecls times, or library-like names
//     (commonNames), are not followed; the mapping escalates to full instead
//     when a caller has one, but the trigger set itself stops there.
//   - permission-check code no authzdiff op reaches (SSO login, admin CLI,
//     start-up, legal hold) is logged and runs nothing: the oracle cannot
//     judge it.
//   - code outside the index (the cli, operator and migrate modules,
//     devtools, scripts) never triggers: authzdiff does not exercise it.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "plan":
		fs := flag.NewFlagSet("plan", flag.ExitOnError)
		base := fs.String("base", "", "base revision (merge base side)")
		head := fs.String("head", "HEAD", "head revision")
		_ = fs.Parse(os.Args[2:])
		if *base == "" {
			usage()
		}
		var p *plan
		p, err = makePlan(*base, *head)
		if err == nil {
			err = p.write(os.Stdout)
		}
	case "inventory":
		fs := flag.NewFlagSet("inventory", flag.ExitOnError)
		rev := fs.String("rev", "HEAD", "revision")
		_ = fs.Parse(os.Args[2:])
		err = inventory(os.Stdout, *rev)
	case "ops":
		var t tree
		if t, err = readTree("HEAD", treeDirs...); err == nil {
			var all []op
			if all, err = authzdiffOps(t); err == nil {
				for _, o := range all {
					fmt.Printf("%s\t%s\n", o.name, o.row)
				}
			}
		}
	case "check-log":
		fs := flag.NewFlagSet("check-log", flag.ExitOnError)
		opsFlag := fs.String("ops", "", "comma-separated planned ops")
		full := fs.Bool("full", false, "the log is a full sweep: its ops must be exactly the parsed op table at HEAD")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			usage()
		}
		var known []string
		if *full {
			var t tree
			var all []op
			if t, err = readTree("HEAD", treeDirs...); err == nil {
				all, err = authzdiffOps(t)
			}
			known = []string{}
			for _, o := range all {
				known = append(known, o.name)
			}
		}
		var b []byte
		if err == nil {
			if b, err = os.ReadFile(fs.Arg(0)); err == nil {
				err = checkLog(b, splitOps(*opsFlag), known)
			}
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "authzgate:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: authzgate plan -base REV [-head REV] | inventory [-rev REV] | check-log -ops a,b LOG")
	os.Exit(2)
}

func splitOps(s string) []string {
	var out []string
	for o := range strings.SplitSeq(s, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// ---------- plan ----------

type mode string

const (
	modeNone mode = "none"
	modeOps  mode = "ops"
	modeFull mode = "full"
)

// fullFraction: a mapping that selects at least this share of all ops runs
// the full sweep instead (the op filter then saves little and the full sweep
// also checks every waiver for dead entries).
const fullFraction = 0.5

// canaryOps run when only the gate's own wiring changed (ci.yml, this tool):
// the job must be exercised, but nothing in the product changed. They are the
// #4332 op and a plain secret op.
var canaryOps = []string{"machine.token.issue", "secret.update"}

type plan struct {
	mode    mode
	ops     []string
	reasons []string
}

func (p *plan) write(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "mode=%s\nops=%s\n", p.mode, strings.Join(p.ops, ","))
	for _, r := range p.reasons {
		fmt.Fprintf(&b, "# %s\n", r)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// escalate raises the plan's mode; full never goes back down.
func (p *plan) escalate(m mode, reason string) {
	p.reasons = append(p.reasons, fmt.Sprintf("%s: %s", m, reason))
	if p.mode == modeFull || m == modeNone {
		return
	}
	if m == modeFull || p.mode == modeNone {
		p.mode = m
	}
}

func makePlan(base, head string) (*plan, error) {
	hunks, err := diffHunks(base, head)
	if err != nil {
		return nil, err
	}
	if len(hunks) == 0 {
		return &plan{mode: modeNone}, nil
	}
	ht, err := readTree(head, treeDirs...)
	if err != nil {
		return nil, err
	}
	bt, err := readTree(base, treeDirs...)
	if err != nil {
		return nil, err
	}
	return planFrom(hunks, ht, bt)
}

// planFrom is the plan for changed lines hunks between base tree bt and head
// tree ht.
func planFrom(hunks map[string]*fileHunks, ht, bt tree) (*plan, error) {
	p := &plan{mode: modeNone}
	m, err := newModel(ht)
	if err != nil {
		return nil, err
	}
	all, err := authzdiffOps(ht)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no ops found in server/authzdiff: the op table moved, update authzgate")
	}

	selected := map[string]bool{}
	for _, f := range sortedKeys(hunks) {
		h := hunks[f]
		switch {
		case f == ".github/workflows/ci.yml":
			p.escalate(modeOps, f+" (gate wiring) changed: canary ops")
			for _, o := range canaryOps {
				selected[o] = true
			}
			continue
		case strings.HasPrefix(f, "scripts/ci/authzgate/") || f == "scripts/ci/authz-oracle.sh":
			p.escalate(modeFull, f+": the gate itself changed")
			continue
		case strings.HasPrefix(f, "server/authzdiff/"):
			p.escalate(modeFull, f+": the oracle itself changed")
			continue
		case strings.HasPrefix(f, "migrations/"):
			if isRBACMigration(f, ht[f]) || isRBACMigration(f, bt[f]) {
				p.escalate(modeFull, f+": RBAC seed migration")
			}
			continue
		case !inScope(f):
			continue
		}
		// head side: the index's own declarations (an in-scope file at head is
		// indexed), so the base side below can match them by identity
		changed := touched(m.ix.byFile[f], h.newLines)
		if src, ok := bt[f]; ok {
			ds, err := parseDecls(f, src)
			if err != nil {
				return nil, err
			}
			for _, d := range touched(ds, h.oldLines) {
				if r := m.reason(d); r != "" && !slices.ContainsFunc(m.ix.byFile[f], func(x *decl) bool { return x.name == d.name && x.recv == d.recv }) {
					p.escalate(modeFull, fmt.Sprintf("%s: %s removed (%s)", f, d.name, r))
				} else if r != "" {
					// still present at head: judge the head declaration
					for _, x := range m.ix.byFile[f] {
						if x.name == d.name && x.recv == d.recv && !slices.Contains(changed, x) {
							changed = append(changed, x)
						}
					}
				}
			}
		}
		for _, d := range changed {
			r := m.reason(d)
			if r == "" {
				continue
			}
			label := fmt.Sprintf("%s: %s (%s)", f, qual(d), r)
			if full := m.forcesFull(d); full != "" {
				p.escalate(modeFull, label+": "+full)
				continue
			}
			transport := strings.HasPrefix(d.file, "server/")
			up, blocked := m.callers(d, transport)
			if len(blocked) > 0 {
				p.escalate(modeFull, fmt.Sprintf("%s: its callers include %d the mapping cannot follow (e.g. %s)", label, len(blocked), blocked[0]))
				continue
			}
			if transport {
				// a handler or service method: the rows it calls are its ops
				for r := range d.refs {
					if m.rows[r] {
						up[r] = true
					}
				}
			}
			n := 0
			for _, o := range all {
				if o.reaches(up) {
					selected[o.name] = true
					n++
				}
			}
			if n == 0 {
				p.escalate(modeNone, label+": no authzdiff op reaches it (outside the oracle's surface)")
				continue
			}
			p.escalate(modeOps, fmt.Sprintf("%s -> %d op(s)", label, n))
		}
	}
	if p.mode == modeOps && float64(len(selected)) >= fullFraction*float64(len(all)) {
		p.escalate(modeFull, fmt.Sprintf("%d of %d ops selected", len(selected), len(all)))
	}
	if p.mode == modeOps {
		p.ops = sortedKeys(selected)
	}
	return p, nil
}

// globalTransport: request-wide authorization in front of every op (REST
// middleware, gRPC interceptors, the router's gate table).
var globalTransport = []string{"server/middleware/", "server/grpc/interceptors/", "server/http/router"}

// forcesFull says why a change to relevant declaration d cannot be mapped to a
// subset of ops, or "".
func (m *model) forcesFull(d *decl) string {
	switch {
	case m.isRoot(d):
		return "a decision root"
	case m.permDefs[d.key()]:
		return "a permission constant"
	case d.kind != kindFunc && m.hasPermLiteral(d):
		return "a permission table"
	case slices.ContainsFunc(globalTransport, func(p string) bool { return strings.HasPrefix(d.file, p) }):
		return "request-wide transport authorization"
	}
	return ""
}

func qual(d *decl) string {
	if d.recv != "" {
		return d.recv + "." + d.name
	}
	return d.name
}

// touched returns the declarations whose line range contains a changed line.
func touched(ds []*decl, lines []int) []*decl {
	var out []*decl
	for _, d := range ds {
		if slices.ContainsFunc(lines, func(l int) bool { return l >= d.start && l <= d.end }) {
			out = append(out, d)
		}
	}
	return out
}

// ---------- diff ----------

type fileHunks struct {
	oldLines, newLines []int
}

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// diffHunks returns the changed line numbers per file of base...head (the
// merge-base diff, as fuzz-plan uses). Renames are off: a moved file is a
// deletion plus an addition, so every declaration in it is judged. A pure
// deletion marks the line it happened after (and the next) on the new side,
// so a check removed from inside a function maps to that function at head.
func diffHunks(base, head string) (map[string]*fileHunks, error) {
	out, err := git("diff", "--no-color", "--no-ext-diff", "--no-renames", "-U0", base+"..."+head)
	if err != nil {
		return nil, fmt.Errorf("git diff %s...%s: %w", base, head, err)
	}
	return parseDiff(out)
}

func parseDiff(out []byte) (map[string]*fileHunks, error) {
	res := map[string]*fileHunks{}
	var cur *fileHunks
	var oldName string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "diff --git "):
			cur, oldName = nil, ""
		case strings.HasPrefix(l, "--- "):
			oldName = strings.TrimPrefix(strings.TrimPrefix(l, "--- "), "a/")
		case strings.HasPrefix(l, "+++ "):
			name := strings.TrimPrefix(strings.TrimPrefix(l, "+++ "), "b/")
			if name == "/dev/null" {
				name = oldName
			}
			if res[name] == nil {
				res[name] = &fileHunks{}
			}
			cur = res[name]
		case strings.HasPrefix(l, "@@ ") && cur != nil:
			mm := hunkHeader.FindStringSubmatch(l)
			if mm == nil {
				return nil, fmt.Errorf("bad hunk header %q", l)
			}
			oStart, oc := atoi(mm[1]), count(mm[2])
			ns, nc := atoi(mm[3]), count(mm[4])
			for i := range oc {
				cur.oldLines = append(cur.oldLines, oStart+i)
			}
			for i := range nc {
				cur.newLines = append(cur.newLines, ns+i)
			}
			if nc == 0 {
				cur.newLines = append(cur.newLines, ns, ns+1)
			}
		}
	}
	return res, sc.Err()
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func count(s string) int {
	if s == "" {
		return 1
	}
	return atoi(s)
}

// ---------- authzdiff ops ----------

// op is one authzdiff operation: its name (what AUTHZDIFF_OPS selects), its
// matrix row (a core method) and every selector name in its op literal (the
// core, REST and gRPC calls it makes).
type op struct {
	name, row string
	refs      map[string]bool
}

func (o op) reaches(up map[string]bool) bool {
	if up[o.row] {
		return true
	}
	for r := range o.refs {
		if up[r] {
			return true
		}
	}
	return false
}

// authzdiffOps reads the op table from server/authzdiff's test files, in two
// shapes: a composite literal with a string `name:` and a string `row:`
// field, and a call of an op constructor (a function whose body builds such a
// literal from its parameters: userOp(name, row, ...), valueRead(name, ...))
// with string literals in those parameter positions. A constructed op's refs
// are its literal's selectors plus the call's arguments' (the closure passed
// in names the core method). check-log closes the loop in CI: a planned op the
// sweep does not run, or (full mode) an op the sweep runs that this parser
// does not know, fails the job.
func authzdiffOps(t tree) ([]op, error) {
	var files []*ast.File
	for _, p := range sortedKeys(t) {
		if !strings.HasPrefix(p, "server/authzdiff/") || !strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, t[p], parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	ctors := map[string]ctor{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				if c, ok := ctorOf(fd); ok {
					ctors[fd.Name.Name] = c
				}
			}
		}
	}
	var out []op
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CompositeLit:
				name, row := litField(v, "name"), litField(v, "row")
				if name == "" || row == "" {
					return true
				}
				o := op{name: name, row: row, refs: map[string]bool{}}
				addSelectors(o.refs, v)
				out = append(out, o)
				return false
			case *ast.CallExpr:
				id, ok := v.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				c, isCtor := ctors[id.Name]
				if !isCtor {
					return true
				}
				o := op{name: strArg(v, c.nameArg), row: c.row, refs: maps.Clone(c.refs)}
				if c.rowArg >= 0 {
					o.row = strArg(v, c.rowArg)
				}
				if o.name == "" || o.row == "" {
					return true
				}
				for _, a := range v.Args {
					addSelectors(o.refs, a)
				}
				out = append(out, o)
				return false
			}
			return true
		})
	}
	slices.SortFunc(out, func(a, b op) int { return strings.Compare(a.name, b.name) })
	return slices.CompactFunc(out, func(a, b op) bool { return a.name == b.name }), nil
}

// ctor is an op constructor: which parameter is the op name, which the row
// (or the row literal), and the selectors of the literal it builds.
type ctor struct {
	nameArg, rowArg int // parameter index; rowArg -1 = row is a literal
	row             string
	refs            map[string]bool
}

func ctorOf(fd *ast.FuncDecl) (ctor, bool) {
	params := map[string]int{}
	i := 0
	for _, f := range fd.Type.Params.List {
		for _, n := range f.Names {
			params[n.Name] = i
			i++
		}
	}
	var c ctor
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || found {
			return !found
		}
		nameP, rowP, rowLit := -1, -1, litField(cl, "row")
		for _, e := range cl.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, ok1 := kv.Key.(*ast.Ident)
			v, ok2 := kv.Value.(*ast.Ident)
			if !ok1 || !ok2 {
				continue
			}
			if idx, ok := params[v.Name]; ok {
				switch k.Name {
				case "name":
					nameP = idx
				case "row":
					rowP = idx
				}
			}
		}
		if nameP < 0 || rowP < 0 && rowLit == "" {
			return true
		}
		c = ctor{nameArg: nameP, rowArg: rowP, row: rowLit, refs: map[string]bool{}}
		addSelectors(c.refs, cl)
		found = true
		return false
	})
	return c, found
}

func litField(cl *ast.CompositeLit, key string) string {
	for _, e := range cl.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		k, ok := kv.Key.(*ast.Ident)
		lit, isLit := kv.Value.(*ast.BasicLit)
		if ok && isLit && k.Name == key && lit.Kind == token.STRING {
			v, _ := strconv.Unquote(lit.Value)
			return v
		}
	}
	return ""
}

func strArg(call *ast.CallExpr, i int) string {
	if i < 0 || i >= len(call.Args) {
		return ""
	}
	lit, ok := call.Args[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	v, _ := strconv.Unquote(lit.Value)
	return v
}

func addSelectors(refs map[string]bool, n ast.Node) {
	ast.Inspect(n, func(x ast.Node) bool {
		if s, ok := x.(*ast.SelectorExpr); ok {
			refs[s.Sel.Name] = true
		}
		return true
	})
}

// ---------- check-log ----------

var (
	sweepSummary = regexp.MustCompile(`sweep: (\d+) cases`)
	subtestPass  = regexp.MustCompile(`--- PASS: TestAuthzDiffSweep/(\S+)`)
	subtestFail  = regexp.MustCompile(`--- FAIL: TestAuthzDiffSweep/(\S+)`)
)

// checkLog fails unless the verbose sweep log shows a non-empty sweep and,
// for an op plan, a finished subtest for every planned op. It does not judge
// pass/fail (go test's exit status does); it rejects the green-but-empty run.
func checkLog(b []byte, ops, known []string) error {
	m := sweepSummary.FindSubmatch(b)
	if m == nil {
		return fmt.Errorf("no 'sweep: N cases' line: the sweep did not run")
	}
	if atoi(string(m[1])) == 0 {
		return fmt.Errorf("the sweep ran 0 cases")
	}
	ran := map[string]bool{}
	for _, re := range []*regexp.Regexp{subtestPass, subtestFail} {
		for _, mm := range re.FindAllSubmatch(b, -1) {
			ran[string(mm[1])] = true
		}
	}
	var missing []string
	for _, o := range ops {
		if !ran[o] {
			missing = append(missing, o)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("planned ops did not run (unknown to the sweep?): %s", strings.Join(missing, ","))
	}
	if known == nil {
		return nil
	}
	// Full sweep: the ops it ran are the whole op table. An op the parser does
	// not know can never be selected in ops mode (the plan under-selects), so
	// a drift fails here, on the PR that changed the op table (a
	// server/authzdiff change always plans full).
	var unknown, unrun []string
	for o := range ran {
		if !slices.Contains(known, o) {
			unknown = append(unknown, o)
		}
	}
	for _, o := range known {
		if !ran[o] {
			unrun = append(unrun, o)
		}
	}
	slices.Sort(unknown)
	if len(unknown) > 0 || len(unrun) > 0 {
		return fmt.Errorf("authzgate's op parser and the sweep disagree: ran but not parsed %v, parsed but not run %v; teach authzdiffOps the new op shape", unknown, unrun)
	}
	return nil
}

// ---------- inventory ----------

func inventory(w io.Writer, rev string) error {
	t, err := readTree(rev, treeDirs...)
	if err != nil {
		return err
	}
	m, err := newModel(t)
	if err != nil {
		return err
	}
	var b strings.Builder
	direct, closure := 0, 0
	for _, d := range m.ix.decls {
		r := m.why[d]
		if r == "" {
			continue
		}
		if strings.HasPrefix(r, "reaches ") {
			closure++
		} else {
			direct++
		}
		fmt.Fprintf(&b, "%s:%d\t%s\t%s\n", d.file, d.start, qual(d), r)
	}
	// The closure's known stop: relevant funcs and vars whose name it cannot
	// follow, so their callers are in the set only if they reach a root some
	// other way.
	stops := 0
	for _, d := range m.ix.decls {
		if m.why[d] != "" && (d.kind == kindFunc || d.kind == kindVar) && !m.carries(d) {
			stops++
			fmt.Fprintf(&b, "# stop: %s:%d\t%s (%d declarations share the name)\n", d.file, d.start, qual(d), len(m.ix.byKey[d.key()]))
		}
	}
	fmt.Fprintf(&b, "# %d declarations indexed, %d in the trigger set (%d direct, %d through the closure), %d roots, %d permission names, %d closure stops\n",
		len(m.ix.decls), direct+closure, direct, closure, len(m.roots), len(m.perms), stops)
	_, err = io.WriteString(w, b.String())
	return err
}
