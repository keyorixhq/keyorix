// Package writeguard is a standalone, test-only sweep over internal/cli that asserts no
// production code calls os.Create/os.OpenFile/os.WriteFile directly for sensitive
// output (exports, bundles, key material, evidence) outside the internal/securefiles
// shared helpers — see keyorix-private/adversarial-review/QUEUE.md "Group 2 guard".
//
// Every call site the sweep finds must either route through securefiles
// (SecureCreateFile/SecureCreateFileSync/SecureCreateFileHandle/SecureWriteFile/
// SecureWriteFileSync) or appear in the allowlist below with a written justification —
// an empty justification, or a call site the sweep can no longer find, fails the test
// (see TestAllowlistJustificationsAreNonEmpty and TestAllowlistEntriesStillExist): this
// keeps the allowlist honest rather than a place stale exemptions accumulate silently.
package writeguard

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// allowlist maps "relative/path/from/internal/cli.go:LINE" to a written justification
// for a raw os.Create/os.OpenFile/os.WriteFile call that intentionally does NOT route
// through internal/securefiles. Every entry was reviewed as part of the Group 2
// safe-file-writes fix; see the justification for why each one is safe/out-of-scope as
// it stands, not merely undiscovered.
//
// This allowlist is meant to generate its own rot and be caught: the four sites
// originally deferred here (migrate_provider.go's copyFile, bundle.go's --out write,
// and both secret/fix.go sites) were deferred specifically because O_EXCL didn't fit
// their semantics -- conflating "which open flags" with "how much of the path gets
// walked safely." Once internal/securefiles.SecureOpenBeneath was exported as a
// standalone walk primitive taking caller-supplied flags (separate from the O_EXCL-only
// SecureCreateFile family), all four were re-examined against that new axis and all four
// turned out to fit it: none of them actually needed the streaming non-exclusive helper
// this comment used to say bundle.go was blocked on. They were fixed directly and
// removed from this list rather than left allowlisted -- if a FUTURE site is added here
// citing "needs a streaming/non-exclusive write," re-check against SecureOpenBeneath
// first; it may already fit, the same way it did for all four sites removed here.
var allowlist = map[string]string{
	"system/init.go:172": "creates an empty (0-byte) placeholder file for the local sqlite DB path purely " +
		"to make first-boot vs. already-initialized unambiguous -- no data is written by " +
		"this call. Already uses O_EXCL for an atomic, idempotent existence check " +
		"(err == nil or IsExist are both treated as success).",
	"system/init.go:202": "creates an empty (0-byte) placeholder file for the local log path, same " +
		"idempotent-existence-check shape as init.go:172 -- no data is written by this call. " +
		"Already uses O_EXCL.",
}

// sensitiveFn is the set of os.* functions this sweep flags.
var sensitiveFn = map[string]bool{
	"Create":    true,
	"OpenFile":  true,
	"WriteFile": true,
}

type site struct {
	relPath string
	line    int
	fn      string
}

func (s site) key() string { return s.relPath + ":" + strconv.Itoa(s.line) }

// cliRoot resolves the internal/cli directory relative to this test file's own
// location (not the process cwd), so the sweep works regardless of how `go test` is
// invoked.
func cliRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must resolve this test file's path")
	// this file lives at internal/cli/writeguard/write_guard_test.go
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), ".."))
	require.NoError(t, err)
	return root
}

// scanFile parses a single .go file and returns every os.Create/os.OpenFile/
// os.WriteFile call site found in it (by AST inspection, not string/regex matching, so
// it isn't fooled by the call appearing in a comment or string literal, and isn't
// blind to unusual formatting).
func scanFile(fset *token.FileSet, path string) ([]site, error) {
	src, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path built from filepath.Walk below, not external input
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []site
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "os" {
			return true
		}
		if !sensitiveFn[sel.Sel.Name] {
			return true
		}
		pos := fset.Position(call.Pos())
		sites = append(sites, site{relPath: path, line: pos.Line, fn: sel.Sel.Name})
		return true
	})
	return sites, nil
}

// findAllSites walks root (internal/cli) recursively, scanning every non-test .go file
// (test fixtures are allowed to build test data with raw os calls; this sweep is about
// production output paths) and returns every raw os.Create/os.OpenFile/os.WriteFile
// call site found, keyed by path relative to root.
func findAllSites(t *testing.T, root string) map[string]site {
	t.Helper()
	fset := token.NewFileSet()
	found := map[string]site{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		sites, serr := scanFile(fset, path)
		if serr != nil {
			return serr
		}
		for _, s := range sites {
			rel, rerr := filepath.Rel(root, s.relPath)
			require.NoError(t, rerr)
			s.relPath = filepath.ToSlash(rel)
			found[s.key()] = s
		}
		return nil
	})
	require.NoError(t, err, "walking %s must not fail", root)
	return found
}

// TestNoUnprotectedSensitiveFileWrites is the Group 2 guard: every raw os.Create/
// os.OpenFile/os.WriteFile call under internal/cli must be explicitly allowlisted
// (with a written justification), i.e. everything else must go through
// internal/securefiles. Verified RED against pre-fix code (it flagged
// compliance/csv_export.go:51, compliance/compliance.go:228, compliance/baseline.go:49,
// rbac/export_matrix.go:79, migrate_provider.go's copyFile, bundle/bundle.go:92, and
// both secret/fix.go sites before those were migrated); GREEN after.
func TestNoUnprotectedSensitiveFileWrites(t *testing.T) {
	root := cliRoot(t)
	found := findAllSites(t, root)

	var unallowed []string
	for key, s := range found {
		if _, ok := allowlist[key]; !ok {
			unallowed = append(unallowed, key+" (os."+s.fn+")")
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"raw os.Create/os.OpenFile/os.WriteFile call(s) for sensitive CLI output found with "+
			"no securefiles routing and no allowlist entry -- route through "+
			"securefiles.SecureCreateFile(Sync|Handle) (or SecureWriteFile(Sync) for an "+
			"intentional-overwrite case), or add a reviewed allowlist entry with a written "+
			"justification: %v", unallowed)
}

// TestAllowlistEntriesStillExist is the flip side of the guard above: an allowlist
// entry for a call site that no longer exists (renamed, deleted, or — worse — silently
// migrated onto securefiles without removing its exemption) would hide a
// regression the moment that exact line shifts. A stale entry doesn't fail the sweep
// above (which only checks found-but-unallowed sites), so it's checked here explicitly.
func TestAllowlistEntriesStillExist(t *testing.T) {
	root := cliRoot(t)
	found := findAllSites(t, root)

	var stale []string
	for key := range allowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"allowlist entry no longer matches any real os.Create/os.OpenFile/os.WriteFile "+
			"call site (the code moved, or was fixed, without updating this list): %v", stale)
}

// TestAllowlistJustificationsAreNonEmpty guards against an allowlist entry added with
// an empty/placeholder reason, per this campaign's standing rule that an exemption
// needs a written justification, not just a line number.
func TestAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range allowlist {
		assert.NotEmpty(t, strings.TrimSpace(reason), "allowlist entry %q has no justification", key)
	}
}

// TestScannerDetectsRawWriteCalls is a self-check on the AST sweep itself: a guard
// that has never been observed to fail on a genuinely bad input is not a guard (a test
// asserting emptiness of a possibly-always-empty scan would pass even if the AST
// matching logic were broken, e.g. matching the wrong selector or the wrong package
// name). This proves the scanner actually detects each of the three flagged os.*
// functions when they're present, independent of internal/cli's current contents.
func TestScannerDetectsRawWriteCalls(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

import "os"

func bad1() { os.Create("x") }
func bad2() { f, _ := os.OpenFile("x", os.O_CREATE, 0600); _ = f }
func bad3() { _ = os.WriteFile("x", nil, 0600) }
func fine() { _, _ = os.ReadFile("x") }
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	fset := token.NewFileSet()
	sites, err := scanFile(fset, path)
	require.NoError(t, err)

	got := map[string]bool{}
	for _, s := range sites {
		got[s.fn] = true
	}
	assert.True(t, got["Create"], "scanner must detect os.Create")
	assert.True(t, got["OpenFile"], "scanner must detect os.OpenFile")
	assert.True(t, got["WriteFile"], "scanner must detect os.WriteFile")
	assert.Len(t, sites, 3, "scanner must not also flag os.ReadFile or find phantom sites")
}
