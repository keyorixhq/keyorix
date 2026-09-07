// mfa_stepup_purpose_guard_test.go — regression guard for the confused-deputy
// MFA step-up bypass fixed alongside this file (models.MFAStepUpGrant gained
// an explicit Purpose field; every CURRENT consumption site now requires an
// exact purpose match rather than accepting any live grant). Nothing
// structurally stops a FUTURE consumption site from repeating the exact
// mistake: calling the grant-lookup primitive and accepting whatever comes
// back without pinning down which purpose is actually required for that
// action -- that purpose-agnostic acceptance is precisely how the original
// bug arose.
//
// This is an AST sweep (go/parser, not string/regex matching) over every
// non-test *.go file in the repository for a call to HasActiveMFAStepUp or
// GetActiveMFAStepUpGrant -- the two functions that turn a stored grant row
// into an authorization decision (see internal/core/mfa_stepup.go and
// internal/core/storage/interface.go). Both share the same argument shape
// (ctx, userID, purpose, ...), so the purpose argument is always the third
// (index 2).
//
// Every call site found must be in mfaStepUpPurposeAllowlist below with a
// written justification, matching the house convention (see
// internal/cli/writeguard/write_guard_test.go,
// internal/core/g80_1530_machine_actor_attribution_guard_test.go). A call
// site is safe when its purpose argument is a HARDCODED
// models.MFAStepUpPurpose* constant matching the allowlist's recorded
// expectation for that exact site -- not a variable, not a struct field, not
// merely non-empty. A site whose purpose argument cannot be resolved to a
// literal constant must say so explicitly in its allowlist entry (expected =
// "") with a reason establishing it is not itself an authorization decision
// (e.g. a storage-layer passthrough forwarding a value some OTHER,
// separately-guarded call site already decided).
//
// This guard's own effectiveness was verified red-then-green: temporarily
// changing internal/core/mfa.go's requireReauth call from
// models.MFAStepUpPurposeReauth to models.MFAStepUpPurposeRestrictedSecretRead
// (recreating the confused-deputy shape -- accepting the ambient
// login-minted grant for an account-security-factor change) made
// TestMFAStepUpConsumersUseExpectedPurpose fail with exactly that mismatch;
// restoring the constant made it pass again.
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mfaStepUpGuardedFuncs is the set of functions this sweep treats as turning
// a stored MFAStepUpGrant into an authorization decision. Both take
// (ctx, userID, purpose, ...) -- the purpose argument is always at index 2.
var mfaStepUpGuardedFuncs = map[string]bool{
	"HasActiveMFAStepUp":      true,
	"GetActiveMFAStepUpGrant": true,
}

// mfaPurposeArgIndex is the zero-based index of the purpose argument shared
// by both guarded functions' signatures.
const mfaPurposeArgIndex = 2

// mfaStepUpAllowEntry records, for one call site (keyed "relpath:line" in
// mfaStepUpPurposeAllowlist), the purpose constant that call site is
// expected to hardcode -- or "" when the site intentionally does not pass a
// literal, with reason explaining why that's still safe.
type mfaStepUpAllowEntry struct {
	expectedPurpose string // e.g. "MFAStepUpPurposeReauth"; "" means intentionally non-literal
	reason          string
}

// mfaStepUpPurposeAllowlist is the exhaustive, reasoned inventory of every
// call to HasActiveMFAStepUp/GetActiveMFAStepUpGrant in the repository. A
// call site missing from this list, or one whose purpose argument no longer
// matches its recorded expectedPurpose, fails
// TestMFAStepUpConsumersUseExpectedPurpose -- exactly the shape a future
// "accept any live grant" regression would take.
var mfaStepUpPurposeAllowlist = map[string]mfaStepUpAllowEntry{
	"internal/core/mfa.go:504": {
		expectedPurpose: "MFAStepUpPurposeReauth",
		reason: "requireReauth's account-security-factor-change gate (DisableMFA, " +
			"RegenerateMFARecoveryCodes, ActivateMFA, WebAuthn credential register/delete, email change). " +
			"Must reject the ambient MFAStepUpPurposeRestrictedSecretRead grant a plain login mints -- " +
			"accepting it here is the exact confused-deputy shape this fix closed (a leaked bearer token " +
			"plus the password would otherwise ride the account owner's own earlier login into an " +
			"account takeover).",
	},
	"internal/core/classification_gate.go:177": {
		expectedPurpose: "MFAStepUpPurposeRestrictedSecretRead",
		reason: "checkRestrictedMFAGate, the classification_restricted_requires_mfa_stepup gate for " +
			"reading a ClassificationRestricted secret's value. Must reject a MFAStepUpPurposeReauth grant " +
			"(minted only for account-security changes) -- the two purposes must never satisfy each other.",
	},
	"internal/core/mfa_stepup.go:81": {
		expectedPurpose: "",
		reason: "HasActiveMFAStepUp's own implementation: forwards the `purpose` PARAMETER it was called " +
			"with straight through to storage.GetActiveMFAStepUpGrant. This is the shared primitive, not a " +
			"consumer -- it has no fixed purpose of its own to hardcode. Enforcement responsibility sits " +
			"with HasActiveMFAStepUp's own callers, which this same allowlist enumerates separately " +
			"(currently just mfa.go:504).",
	},
	"server/http/handlers/mfa_stepup_proxy.go:63": {
		expectedPurpose: "",
		reason: "GetActiveMFAStepUpGrantProxy: the server-side passthrough backing RemoteStorage's " +
			"GetActiveMFAStepUpGrant for a storage.type: remote spoke node (ADR-049). Forwards the wire " +
			"body's Purpose field verbatim -- it makes no policy decision itself (see this file's own doc " +
			"comment: \"no policy decisions made here\"). The actual authorization decision, and the " +
			"literal purpose constant used to make it, lives entirely on the calling core.KeyorixCore side " +
			"(mfa.go:504 / classification_gate.go:177 above), which is unaffected by which storage backend " +
			"(Local or Remote) it happens to be wired to.",
	},
}

type mfaStepUpSite struct {
	relPath string
	line    int
	fn      string
	purpose string // "" when the purpose argument isn't a literal models.MFAStepUpPurpose* constant
}

func (s mfaStepUpSite) key() string { return s.relPath + ":" + strconv.Itoa(s.line) }

// mfaStepUpGuardRepoRoot locates the repository root relative to this test
// file's own location on disk (internal/core), not the test runner's cwd.
func mfaStepUpGuardRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must resolve this test file's path")
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	require.NoError(t, err)
	return root
}

// mfaStepUpPurposeLiteral extracts the models.MFAStepUpPurpose* constant name
// from expr, or "" if expr is not a bare `models.<Ident>` selector -- i.e.
// not a literal, hardcoded reference (a variable, a struct field like
// body.Purpose, a function call, etc. all yield "").
func mfaStepUpPurposeLiteral(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "models" {
		return ""
	}
	if !strings.HasPrefix(sel.Sel.Name, "MFAStepUpPurpose") {
		return ""
	}
	return sel.Sel.Name
}

// scanMFAStepUpFile parses a single .go file and returns every call site to
// a guarded function found in it, by AST inspection.
func scanMFAStepUpFile(fset *token.FileSet, path string) ([]mfaStepUpSite, error) {
	src, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path built from filepath.WalkDir below, not external input
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []mfaStepUpSite
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !mfaStepUpGuardedFuncs[sel.Sel.Name] {
			return true
		}
		purpose := ""
		if len(call.Args) > mfaPurposeArgIndex {
			purpose = mfaStepUpPurposeLiteral(call.Args[mfaPurposeArgIndex])
		}
		pos := fset.Position(call.Pos())
		sites = append(sites, mfaStepUpSite{relPath: path, line: pos.Line, fn: sel.Sel.Name, purpose: purpose})
		return true
	})
	return sites, nil
}

// mfaStepUpGuardSkipDirs mirrors the skip list used by this campaign's other
// repo-wide guards (e.g. g80_1530_machine_actor_attribution_guard_test.go).
var mfaStepUpGuardSkipDirs = map[string]bool{
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

// findAllMFAStepUpSites walks every non-test *.go file in the repository and
// returns every guarded-function call site found, keyed by path relative to
// the repo root plus line number.
func findAllMFAStepUpSites(t *testing.T, repo string) map[string]mfaStepUpSite {
	t.Helper()
	fset := token.NewFileSet()
	found := map[string]mfaStepUpSite{}
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if mfaStepUpGuardSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		sites, serr := scanMFAStepUpFile(fset, path)
		if serr != nil {
			return serr
		}
		for _, s := range sites {
			rel, rerr := filepath.Rel(repo, path)
			require.NoError(t, rerr)
			s.relPath = filepath.ToSlash(rel)
			found[s.key()] = s
		}
		return nil
	})
	require.NoError(t, err, "walking %s must not fail", repo)
	return found
}

// TestMFAStepUpConsumersUseExpectedPurpose is the guard: every call to
// HasActiveMFAStepUp/GetActiveMFAStepUpGrant repo-wide must be in
// mfaStepUpPurposeAllowlist, and every allowlisted site with a non-empty
// expectedPurpose must actually pass that exact literal constant as its
// purpose argument. A site that used to pass the right constant and now
// passes a different one (or a non-literal) fails here -- this is exactly
// the shape a reintroduced "accept any live grant" bug takes: a call site
// that no longer pins down which purpose it actually requires.
func TestMFAStepUpConsumersUseExpectedPurpose(t *testing.T) {
	found := findAllMFAStepUpSites(t, mfaStepUpGuardRepoRoot(t))

	var unlisted []string
	var mismatched []string
	for key, s := range found {
		entry, ok := mfaStepUpPurposeAllowlist[key]
		if !ok {
			unlisted = append(unlisted, key+" ("+s.fn+")")
			continue
		}
		if entry.expectedPurpose == "" {
			continue // intentionally non-literal / not a decision site; reason lives in the allowlist
		}
		if s.purpose != entry.expectedPurpose {
			got := s.purpose
			if got == "" {
				got = "<not a hardcoded models.MFAStepUpPurpose* literal>"
			}
			mismatched = append(mismatched, key+": expected purpose "+entry.expectedPurpose+", found "+got)
		}
	}
	sort.Strings(unlisted)
	sort.Strings(mismatched)

	assert.Empty(t, unlisted,
		"call site(s) to HasActiveMFAStepUp/GetActiveMFAStepUpGrant found with no reviewed allowlist "+
			"entry -- a new MFA step-up grant consumer must hardcode the exact models.MFAStepUpPurpose* "+
			"constant it requires and add a justified entry to mfaStepUpPurposeAllowlist, or it risks "+
			"repeating the confused-deputy bug this guard exists to catch: %v", unlisted)
	assert.Empty(t, mismatched,
		"call site(s) to HasActiveMFAStepUp/GetActiveMFAStepUpGrant no longer pass the purpose constant "+
			"mfaStepUpPurposeAllowlist expects -- this is exactly the bug shape this guard exists to catch: "+
			"a grant consumer accepting a purpose other than the one it actually requires: %v", mismatched)
}

// TestMFAStepUpPurposeAllowlistEntriesStillExist catches a stale allowlist
// entry -- the call site moved, was renamed, or was deleted -- which would
// otherwise silently stop protecting anything.
func TestMFAStepUpPurposeAllowlistEntriesStillExist(t *testing.T) {
	found := findAllMFAStepUpSites(t, mfaStepUpGuardRepoRoot(t))

	var stale []string
	for key := range mfaStepUpPurposeAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"mfaStepUpPurposeAllowlist entry no longer matches any real "+
			"HasActiveMFAStepUp/GetActiveMFAStepUpGrant call site (the code moved, was renamed, or was "+
			"removed, without updating this list): %v", stale)
}

// TestMFAStepUpPurposeAllowlistJustificationsAreNonEmpty guards against an
// allowlist entry added with an empty/placeholder reason.
func TestMFAStepUpPurposeAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, entry := range mfaStepUpPurposeAllowlist {
		assert.NotEmpty(t, strings.TrimSpace(entry.reason), "allowlist entry %q has no justification", key)
	}
}

// TestMFAStepUpPurposeScannerDetectsCallSites is a self-check on the AST
// sweep: proves it actually extracts a hardcoded purpose constant when one
// is present, and correctly reports "" (non-literal) for a dynamic argument
// -- independent of the repository's current contents, so this guard can
// never pass merely because it never finds anything.
func TestMFAStepUpPurposeScannerDetectsCallSites(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

import "github.com/keyorixhq/keyorix/internal/storage/models"

func hardcoded(c interface{ HasActiveMFAStepUp(int, int, models.MFAStepUpPurpose) (bool, error) }) {
	_, _ = c.HasActiveMFAStepUp(0, 0, models.MFAStepUpPurposeReauth)
}

func dynamic(c interface{ HasActiveMFAStepUp(int, int, models.MFAStepUpPurpose) (bool, error) }, p models.MFAStepUpPurpose) {
	_, _ = c.HasActiveMFAStepUp(0, 0, p)
}

func other(c interface{ SomethingElse() }) {
	c.SomethingElse()
}
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	fset := token.NewFileSet()
	sites, err := scanMFAStepUpFile(fset, path)
	require.NoError(t, err)
	require.Len(t, sites, 2, "scanner must find exactly the two HasActiveMFAStepUp calls, not SomethingElse")

	byLine := map[int]mfaStepUpSite{}
	for _, s := range sites {
		byLine[s.line] = s
	}
	var gotHardcoded, gotDynamic bool
	for _, s := range sites {
		if s.purpose == "MFAStepUpPurposeReauth" {
			gotHardcoded = true
		}
		if s.purpose == "" {
			gotDynamic = true
		}
	}
	assert.True(t, gotHardcoded, "scanner must extract the literal MFAStepUpPurposeReauth constant")
	assert.True(t, gotDynamic, "scanner must report \"\" for a non-literal (variable) purpose argument")
}
