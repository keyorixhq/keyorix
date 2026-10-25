// clock_seam_guard_test.go — #1983: KeyorixCore.SetClockForTesting and
// OIDCVerifier.setClock exist so a test or fuzz harness can drive every
// clock-based authorization/expiry decision (sessions, PATs, machine tokens,
// shares, dynamic secrets, MFA, impersonation, and JWT/OIDC verification) off
// one injected value. Production code must never call either -- a live call
// site could swap the clock governing all of those decisions for the rest of
// the process, or for one request if raced against a concurrent request using
// the same *KeyorixCore. This is exactly the "test-only capability leaks into
// a live code path" gap bcrypt_cost.go's own #G63 comment already flags as
// unenforced for SetBcryptCostForTesting in this same package -- this guard
// is the enforcement that gap is missing, applied to the new clock seam
// before it can accumulate the same kind of undocumented drift.
//
// Recognized forms: any SelectorExpr named SetClockForTesting, setClock or
// StorageForTesting, called or not (a method value `f := c.StorageForTesting`
// or a method expression `(*KeyorixCore).SetClockForTesting` is a use too, PR
// #3695 re-review N7), found anywhere in a non-_test.go file
// repo-wide, OUTSIDE the literal body of the FuncDecl that IS
// SetClockForTesting or setClock (service.go's SetClockForTesting
// legitimately calls oidc.go's setClock once, to propagate one clock to an
// already-wired OIDCVerifier -- that's the seam's own implementation, not a
// violation). Scoped repo-wide, not just internal/core: SetClockForTesting is
// exported, so any package could in principle call it.
//
// What this guard silently skips (known gaps, deliberately not fixed here):
//   - It matches by NAME on the selector. A reflective lookup such as
//     reflect.ValueOf(c).MethodByName("StorageForTesting") carries the name in a
//     string literal, not a SelectorExpr, so it is not seen.
//   - Any FuncDecl named SetClockForTesting, setClock or StorageForTesting, in
//     any package, is exempt inside its own body. A same-named wrapper elsewhere
//     therefore hides nothing it calls from this scan, but it only matters if the
//     wrapper is itself called from production, and that call IS caught.
//   - Only .go files outside _test.go are scanned, and the walk skips the
//     directories in clockSeamGuardSkipDirs (web/, vendor/, ...). It does not
//     skip .claude-worktrees/, so a local run in a checkout containing that
//     folder can flag other worktrees' files; CI is unaffected.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"

	"github.com/stretchr/testify/require"
)

// clockSeamGuardedFuncs is the set of function/method names this guard treats
// as the test-only clock seam.
//
// StorageForTesting is ADR-121's storage seam for tests moved out of
// internal/core (decision 2): the raw storage handle behind every
// authorization check, for _test.go callers only. It is listed before the
// method exists so the first production caller fails here.
var clockSeamGuardedFuncs = map[string]bool{
	"SetClockForTesting": true,
	"setClock":           true,
	"StorageForTesting":  true,
}

// clockSeamGuardSkipDirs mirrors the skip list used by this campaign's other
// repo-wide guards (e.g. mfa_stepup_purpose_guard_test.go,
// g80_1530_machine_actor_attribution_guard_test.go).
var clockSeamGuardSkipDirs = map[string]bool{
	".git":         true,
	".github":      true,
	".githooks":    true,
	".semgrep":     true,
	".task":        true,
	".scratch":     true,
	"node_modules": true,
	"web":          true,
	"vendor":       true,
}

type clockSeamSite struct {
	relPath string
	line    int
	fn      string
}

// clockSeamGuardRepoRoot locates the repository root relative to this test
// file's own location on disk (internal/core), not the test runner's cwd.
func clockSeamGuardRepoRoot(t *testing.T) string {
	t.Helper()
	thisFile := filepath.Join(srcpath.PkgDir(), "clock_seam_guard_test.go")
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	require.NoError(t, err)
	return root
}

// scanClockSeamFile parses a single .go file and returns every use (call,
// method value, method expression) of a guarded name found in it, EXCLUDING uses found inside the literal
// body of a FuncDecl whose own name is itself a guarded name -- that body is
// the seam's definition, not a caller of it.
func scanClockSeamFile(fset *token.FileSet, path string) ([]clockSeamSite, error) {
	src, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path from filepath.WalkDir below, not external input
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []clockSeamSite
	record := func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !clockSeamGuardedFuncs[sel.Sel.Name] {
			return true
		}
		pos := fset.Position(sel.Pos())
		sites = append(sites, clockSeamSite{relPath: path, line: pos.Line, fn: sel.Sel.Name})
		return true
	}
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && clockSeamGuardedFuncs[fd.Name.Name] {
			continue // the seam's own definition -- exempt, see file doc comment
		}
		ast.Inspect(decl, record)
	}
	return sites, nil
}

// findAllClockSeamSites walks every non-test *.go file in the repository and
// returns every guarded-function call site found, keyed by path relative to
// the repo root plus line number.
func findAllClockSeamSites(t *testing.T, repo string) []clockSeamSite {
	t.Helper()
	fset := token.NewFileSet()
	var found []clockSeamSite
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if clockSeamGuardSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		sites, serr := scanClockSeamFile(fset, path)
		if serr != nil {
			return serr
		}
		for _, s := range sites {
			rel, rerr := filepath.Rel(repo, path)
			require.NoError(t, rerr)
			s.relPath = filepath.ToSlash(rel)
			found = append(found, s)
		}
		return nil
	})
	require.NoError(t, err, "walking %s must not fail", repo)
	return found
}

// TestClockSeamNeverCalledOutsideItsOwnDefinition is the guard: fails if any
// non-_test.go file anywhere in the repository uses SetClockForTesting or
// setClock from outside the seam's own definition. See the file doc comment
// for exactly what "own definition" excludes and why.
func TestClockSeamNeverCalledOutsideItsOwnDefinition(t *testing.T) {
	repo := clockSeamGuardRepoRoot(t)
	sites := findAllClockSeamSites(t, repo)
	if len(sites) == 0 {
		return
	}
	lines := make([]string, 0, len(sites))
	for _, s := range sites {
		if s.fn == "StorageForTesting" {
			lines = append(lines, s.relPath+":"+strconv.Itoa(s.line)+" uses StorageForTesting"+
				" outside its own definition -- this is a test-only storage seam (ADR-121 decision 2); "+
				"a production call site gets the raw storage handle and bypasses every authorization check in core")
			continue
		}
		lines = append(lines, s.relPath+":"+strconv.Itoa(s.line)+" uses "+s.fn+
			" outside its own definition -- this is a test/fuzz-only clock seam; "+
			"a production call site can swap the clock governing every session/PAT/"+
			"machine-token/share/MFA/impersonation expiry decision and JWT verification "+
			"this process makes")
	}
	sort.Strings(lines)
	t.Fatalf("clock-seam guard violated:\n%s", strings.Join(lines, "\n"))
}

// TestClockSeamScanCatchesStorageSeamCall: the guard recognises a production
// call to StorageForTesting (ADR-121) and exempts the method's own definition.
func TestClockSeamScanCatchesStorageSeamCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leaf.go")
	src := "package core\n" +
		"func (c *KeyorixCore) StorageForTesting() Storage { return c.storage }\n" +
		"func (c *KeyorixCore) handler() { _ = c.StorageForTesting() }\n"
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
	sites, err := scanClockSeamFile(token.NewFileSet(), path)
	require.NoError(t, err)
	require.Len(t, sites, 1, "one production call, the definition exempt: %v", sites)
	require.Equal(t, "StorageForTesting", sites[0].fn)
	require.Equal(t, 3, sites[0].line)
}

// TestClockSeamScanCatchesMethodValues: PR #3695 re-review N7. A method value
// or method expression of a guarded seam is a use even without a call at the
// selector (f := c.StorageForTesting; f()).
func TestClockSeamScanCatchesMethodValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leaf.go")
	src := "package core\n" +
		"func (c *KeyorixCore) handler() { f := c.StorageForTesting; _ = f() }\n" +
		"func (c *KeyorixCore) other() { g := (*KeyorixCore).SetClockForTesting; g(c, nil) }\n" +
		"func wire(v *OIDCVerifier) func(func() time.Time) { return v.setClock }\n"
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
	sites, err := scanClockSeamFile(token.NewFileSet(), path)
	require.NoError(t, err)
	got := make([]string, 0, len(sites))
	for _, s := range sites {
		got = append(got, strconv.Itoa(s.line)+":"+s.fn)
	}
	require.Equal(t, []string{"2:StorageForTesting", "3:SetClockForTesting", "4:setClock"}, got)
}
