package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

const secretenvImportPath = "github.com/keyorixhq/keyorix/internal/secretenv"

// liveSecretenvLookups returns one "file:line: ..." entry for every reference to
// secretenv.Lookup in src, a call or a bare reference (`f := secretenv.Lookup`),
// under whatever local name the package is imported. secretenv.Lookup resolves
// <NAME> or <NAME>_FILE against the live environment on every call, so each
// variable it is asked for has a *_FILE form by construction.
func liveSecretenvLookups(t *testing.T, filename string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	require.NoError(t, err)
	local := ""
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		require.NoError(t, uerr)
		if p != secretenvImportPath {
			continue
		}
		local = "secretenv"
		if imp.Name != nil {
			local = imp.Name.Name
		}
	}
	if local == "" || local == "_" {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Lookup" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == local {
			out = append(out, fset.Position(sel.Pos()).String())
		}
		return true
	})
	return out
}

// TestNoLiveSecretenvLookupOfFileCapableVars is the class guard for #3830
// (CONFIG-TRUTH-1): non-test code under server/ must not call secretenv.Lookup.
// config.Load reads every non-key-material *_FILE secret once, from the
// descriptor whose permissions EnforceSecretFilePermissions judges
// (SECRETENV-REVIEW-1 F5/F6); a server caller that re-opens the file through
// secretenv.Lookup can use bytes the check never saw. The snapshot is the single
// accessor: config.LookupSecretEnv. Key material is read through
// secretenv.LookupChecked, which judges its own descriptor, and is not flagged.
//
// It reports through guardrules.Rollout (report-only on pull requests).
//
// It does NOT catch: a *_FILE read written by hand (os.Getenv(name+"_FILE") then
// os.ReadFile), a dot-import of secretenv, or the same call outside server/
// (internal/, cli/): those packages have their own readers and are out of
// this guard's scope. TestLiveSecretenvLookupDetector_* calibrates the detector.
func TestNoLiveSecretenvLookupOfFileCapableVars(t *testing.T) {
	g := guardrules.Rollout(t)
	var hits []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "node_modules" || (n != "." && strings.HasPrefix(n, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		hits = append(hits, liveSecretenvLookups(t, path, nil)...)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(hits)
	for _, h := range hits {
		g.Errorf("%s: secretenv.Lookup reads the live environment; answer a *_FILE-capable secret from the boot snapshot with config.LookupSecretEnv (key material: secretenv.LookupChecked)", h)
	}
}

// The two call sites #3830 named, verbatim from main before CONFIG-TRUTH-1.
const preFixBootstrapSite = `package main

import "github.com/keyorixhq/keyorix/internal/secretenv"

func resolveBootstrapToken() (string, error) {
	v, found, err := secretenv.Lookup("KEYORIX_BOOTSTRAP_TOKEN")
	_, _ = found, err
	return v, nil
}
`

const preFixVaultSite = `package main

import (
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

func resolveVaultToken(tokenEnv string) (string, error) {
	v, _, err := secretenv.Lookup(tokenEnv)
	return v, err
}
`

// Red: the detector flags both old sites, and an aliased import and a bare
// function reference. Green: the snapshot accessor and LookupChecked are not flagged.
func TestLiveSecretenvLookupDetector_Calibration(t *testing.T) {
	require.Len(t, liveSecretenvLookups(t, "bootstrap_token.go", preFixBootstrapSite), 1, "old bootstrap site must be red")
	require.Len(t, liveSecretenvLookups(t, "wire_backend_rotation.go", preFixVaultSite), 1, "old vault site must be red")
	require.Len(t, liveSecretenvLookups(t, "alias.go", `package main
import se "github.com/keyorixhq/keyorix/internal/secretenv"
var lookup = se.Lookup
`), 1, "an aliased import is still flagged")
	require.Empty(t, liveSecretenvLookups(t, "green.go", `package main
import (
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)
func f() {
	_, _, _ = config.LookupSecretEnv("KEYORIX_BOOTSTRAP_TOKEN")
	_, _, _ = secretenv.LookupChecked("KEYORIX_MASTER_PASSWORD")
}
`), "the snapshot accessor and LookupChecked are green")
	require.Empty(t, liveSecretenvLookups(t, "unrelated.go", `package main
type x struct{}
func (x) Lookup() {}
func f() { x{}.Lookup() }
`), "a Lookup method on another type is green")
}
