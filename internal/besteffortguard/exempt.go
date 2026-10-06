package besteffortguard

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"sort"
	"strings"
)

// Guard kinds — the THIRD column of docs/besteffort-exempt.tsv, which says how
// the row's own safety claim is verified rather than leaving it as prose.
//
// Every exemption asserts the same thing: "a panic in this discarded call
// cannot escape to misreport an already-committed write." v1 asserted that in
// a reason string and nothing checked it. These kinds make the common cases
// machine-checked.
const (
	// GuardCalleeRecovers: the callee's OWN body recovers. Verified by
	// VerifyExemptionGuards, which requires a recover() inside a defer in that
	// function's body.
	GuardCalleeRecovers = "callee-recovers"
	// GuardCalleeRecoversVia is "callee-recovers-via:<fn>": the callee is a
	// thin wrapper whose panic safety comes from a single choke point one or
	// more hops down (e.g. writeAuditEventFull -> writeAuditEventDiff ->
	// emitAudit). Verified by requiring a recover() in <fn>'s body AND that
	// <fn> is reachable from the callee through package-local calls.
	GuardCalleeRecoversViaPrefix = "callee-recovers-via:"
	// GuardSiteReviewed: a human claim about this one call site that no derived
	// check covers. The escape hatch, not the default -- a row using it must
	// say in its reason why neither of the above applies.
	GuardSiteReviewed = "site-reviewed"
)

// Exemption is one reviewed row of docs/besteffort-exempt.tsv.
type Exemption struct {
	Key    Key
	Guard  string
	Reason string
	Line   int
}

// CalleeWildcard is the Func value of a callee-level exemption: "this callee is
// its own panic choke point, so ANY caller discarding its result is safe."
//
// This is the opposite shape from v1's whole-function key, and the difference
// matters. v1 keyed on the enclosing FUNCTION, which made a row a blanket
// pardon for that function's whole body -- a new, unprotected discard of a
// DIFFERENT callee added to an already-exempt function was absorbed silently.
// A wildcard on the CALLEE cannot do that: it pardons exactly one callee, named
// in the key, and a new discard of anything else is still a fresh hit. It is
// also the honest shape for the claim being made, which was never about the
// caller -- "emitAudit recovers its own panic" is a fact about emitAudit, true
// at all 30-odd of its call sites, and writing it 30 times would invite the
// rows to drift apart rather than keep them in step.
const CalleeWildcard = "*"

// LoadExemptions reads path and returns the exemptions whose package prefix is
// pkgPrefix, keyed by (function, callee).
//
// Row format: "<package>:<function>#<callee>\t<guard>\t<reason>", where
// <function> may be "*" for a callee-level row (see CalleeWildcard).
func LoadExemptions(path, pkgPrefix string) (map[Key]Exemption, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed in-repo path, read from a guard test
	if err != nil {
		return nil, fmt.Errorf("besteffortguard: cannot read %s: %w", path, err)
	}
	out := map[Key]Exemption{}
	prefix := pkgPrefix + ":"
	for i, line := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rawKey, guard, reason, err := splitExemptionRow(path, lineNo, trimmed)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(rawKey, prefix) {
			// Another package's row. Its SHAPE is still validated above, so a
			// malformed row cannot hide in whichever package isn't scanned.
			continue
		}
		k, err := parseExemptionKey(path, lineNo, strings.TrimPrefix(rawKey, prefix))
		if err != nil {
			return nil, err
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("besteffortguard: %s:%d: duplicate exemption %q", path, lineNo, k)
		}
		out[k] = Exemption{Key: k, Guard: guard, Reason: reason, Line: lineNo}
	}
	return out, nil
}

func splitExemptionRow(path string, lineNo int, trimmed string) (rawKey, guard, reason string, err error) {
	fields := strings.Split(trimmed, "\t")
	if len(fields) < 3 {
		return "", "", "", fmt.Errorf("besteffortguard: %s:%d: expected 3 tab-separated fields (<package>:<function>#<callee>, guard, reason), got %d in %q",
			path, lineNo, len(fields), trimmed)
	}
	rawKey = strings.TrimSpace(fields[0])
	guard = strings.TrimSpace(fields[1])
	reason = strings.TrimSpace(strings.Join(fields[2:], " "))
	if !strings.Contains(rawKey, ":") || !strings.Contains(rawKey, "#") {
		return "", "", "", fmt.Errorf("besteffortguard: %s:%d: key %q must be \"<package>:<function>#<callee>\"", path, lineNo, rawKey)
	}
	if guard != GuardCalleeRecovers && guard != GuardSiteReviewed && !strings.HasPrefix(guard, GuardCalleeRecoversViaPrefix) {
		return "", "", "", fmt.Errorf("besteffortguard: %s:%d: guard %q must be %q, %q<fn>, or %q",
			path, lineNo, guard, GuardCalleeRecovers, GuardCalleeRecoversViaPrefix, GuardSiteReviewed)
	}
	// A one-word "reason" is a suppression wearing a reason's clothes.
	if len(reason) < 40 {
		return "", "", "", fmt.Errorf("besteffortguard: %s:%d: reason is %d chars; an exemption must explain why a panic in this discarded call cannot misreport an already-committed write",
			path, lineNo, len(reason))
	}
	return rawKey, guard, reason, nil
}

func parseExemptionKey(path string, lineNo int, fnAndCallee string) (Key, error) {
	fn, callee, found := strings.Cut(fnAndCallee, "#")
	if !found || fn == "" || callee == "" {
		return Key{}, fmt.Errorf("besteffortguard: %s:%d: key %q must be \"<function>#<callee>\" (or \"*#<callee>\" for a callee-level row) -- a function-only key would pardon every discard in that function, including one added later for a different callee",
			path, lineNo, fnAndCallee)
	}
	if callee == CalleeWildcard {
		return Key{}, fmt.Errorf("besteffortguard: %s:%d: key %q wildcards the CALLEE, which would pardon every discard in that function -- exactly the v1 whole-function key this format replaced. Wildcard the function instead (\"*#%s\") only if the claim really is about the callee",
			path, lineNo, fnAndCallee, fn)
	}
	return Key{Func: fn, Callee: callee}, nil
}

// match returns the exemption covering h, preferring an exact site row over a
// callee-level one.
func match(h Hit, exempt map[Key]Exemption) (Exemption, Key, bool) {
	site := Key{Func: h.Func, Callee: h.Callee}
	if e, ok := exempt[site]; ok {
		return e, site, true
	}
	wild := Key{Func: CalleeWildcard, Callee: h.Callee}
	if e, ok := exempt[wild]; ok {
		return e, wild, true
	}
	return Exemption{}, site, false
}

// Unclassified returns the hits with no matching exemption, one line per
// (function, callee) pair -- repeated call sites of the same pair collapse,
// since one exemption answers for all of them.
func Unclassified(hits []Hit, exempt map[Key]Exemption) []string {
	seen := map[Key]bool{}
	var out []string
	for _, h := range hits {
		if _, _, ok := match(h, exempt); ok {
			continue
		}
		k := Key{Func: h.Func, Callee: h.Callee}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, fmt.Sprintf("%s#%s (%s): %s discard of %s@%d follows write %s@%d",
			h.Func, h.Callee, h.File, h.Kind, h.DiscardCall, h.DiscardLine, h.WriteCall, h.WriteLine))
	}
	sort.Strings(out)
	return out
}

// StaleExemptions returns the exemption keys that match no hit in the current
// scan.
//
// This is the half of #2561's review that mattered most, because its absence is
// what let the file look like evidence. Measured against the v1 guard itself,
// SEVEN of its twelve internal/core rows pardoned zero hits -- the coordinator
// spotted evictUserSessionCache; deleteSessionsForUserAndEvict, emitAudit,
// evictMachineIdentityCacheOrFlush, notifyBreakGlassAdmins,
// revokeProjectDynamicSecretLeases and seedProjectEnvironment were the same
// mistake, all six keyed as if they were enclosing functions when the claim
// being made was about them as CALLEES.
//
// A pardon for nothing is not harmless. It is indistinguishable, to anyone
// reading the file, from a load-bearing one, so the row count overstates how
// much the guard found: twelve rows for five hits of one single callee. And a
// row that goes stale because the hit it pardoned was FIXED leaves that fix
// un-guarded -- the shape can come back and land straight into a pardon that
// is already there.
func StaleExemptions(hits []Hit, exempt map[Key]Exemption) []string {
	used := map[Key]bool{}
	for _, h := range hits {
		if _, k, ok := match(h, exempt); ok {
			used[k] = true
		}
	}
	var out []string
	for k, e := range exempt {
		if !used[k] {
			out = append(out, fmt.Sprintf("%s (line %d)", k, e.Line))
		}
	}
	sort.Strings(out)
	return out
}

// VerifyExemptionGuards checks each exemption's OWN safety claim against the
// scanned source, so a row cannot assert panic-safety that isn't there.
//
//   - callee-recovers: the named callee's body must defer a recover().
//   - callee-recovers-via:<fn>: <fn>'s body must defer a recover(), AND <fn> must
//     be reachable from the callee through package-local calls (so the row names
//     the real choke point, not an unrelated function that happens to recover).
//   - site-reviewed: not checkable here; skipped, which is why it must justify
//     itself in prose.
//
// Returns one message per failing row.
func VerifyExemptionGuards(root string, exempt map[Key]Exemption) ([]string, error) {
	fset := token.NewFileSet()
	files, err := parsePackageFiles(fset, root)
	if err != nil {
		return nil, err
	}
	bodies := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				bodies[fd.Name.Name] = fd
			}
		}
	}

	var problems []string
	keys := make([]Key, 0, len(exempt))
	for k := range exempt {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

	for _, k := range keys {
		problems = append(problems, verifyOneGuard(root, k, exempt[k], bodies)...)
	}
	return problems, nil
}

func verifyOneGuard(root string, k Key, e Exemption, bodies map[string]*ast.FuncDecl) []string {
	if e.Guard == GuardSiteReviewed {
		return nil
	}
	if e.Guard == GuardCalleeRecovers {
		fd, ok := bodies[k.Callee]
		if !ok {
			return []string{fmt.Sprintf("%s (line %d): guard %q but no function %q is declared in %s",
				k, e.Line, e.Guard, k.Callee, root)}
		}
		if !bodyDefersRecover(fd.Body) {
			return []string{fmt.Sprintf("%s (line %d): guard %q but %s's body has no deferred recover()",
				k, e.Line, e.Guard, k.Callee)}
		}
		return nil
	}
	// callee-recovers-via:<fn>
	via := strings.TrimPrefix(e.Guard, GuardCalleeRecoversViaPrefix)
	vfd, ok := bodies[via]
	if !ok {
		return []string{fmt.Sprintf("%s (line %d): guard names %q as the choke point, but no such function is declared in %s",
			k, e.Line, via, root)}
	}
	var problems []string
	if !bodyDefersRecover(vfd.Body) {
		problems = append(problems, fmt.Sprintf("%s (line %d): guard names %q as the choke point, but its body has no deferred recover()",
			k, e.Line, via))
	}
	if _, ok := bodies[k.Callee]; !ok {
		return append(problems, fmt.Sprintf("%s (line %d): callee %q is not declared in %s",
			k, e.Line, k.Callee, root))
	}
	if !reaches(bodies, k.Callee, via) {
		problems = append(problems, fmt.Sprintf("%s (line %d): guard claims %q funnels through %q, but no package-local call path from %s reaches it",
			k, e.Line, k.Callee, via, k.Callee))
	}
	return problems
}

// bodyDefersRecover reports whether body contains a deferred recover() -- either
// `defer func(){ ... recover() ... }()` or `defer besteffort.RunRecover(...)()`.
func bodyDefersRecover(body *ast.BlockStmt) bool {
	if funcHasRunRecoverGuard(body) {
		return true
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		ast.Inspect(ds, func(m ast.Node) bool {
			if call, ok := m.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "recover" {
					found = true
				}
			}
			return true
		})
		return true
	})
	return found
}

// reaches reports whether target is reachable from start through package-local
// calls, bounded by the set of declared functions (so it terminates on cycles).
func reaches(bodies map[string]*ast.FuncDecl, start, target string) bool {
	visited := map[string]bool{}
	var walk func(name string) bool
	walk = func(name string) bool {
		if name == target {
			return true
		}
		if visited[name] {
			return false
		}
		visited[name] = true
		fd, ok := bodies[name]
		if !ok {
			return false
		}
		hit := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if hit {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var callee string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				callee = fn.Name
			case *ast.SelectorExpr:
				callee = fn.Sel.Name
			}
			if callee != "" && walk(callee) {
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	return walk(start)
}
