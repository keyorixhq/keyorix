// second_factor_clearer_callers_guard_test.go — design section 1 of
// docs/design/recovery-options.md (MFA-RESET-TESTS-1).
//
// A second factor is removed by exactly two storage methods: DeleteMFAForUser
// (TOTP secret and recovery codes) and DeleteWebAuthnCredential (one passkey).
// It is switched off, rows kept, by the flag setters SetUserMFAEnabled(false) and
// SetUserWebAuthnEnabled(false), or by clearing User.MFAEnabled /
// User.WebAuthnEnabled on a row written back in full (UpdateUser) (#3801 b):
// with the flag off the login never asks for the factor, so these are clearers
// too.
// Every caller must be a flow that proves who is asking or that two people
// approved: the user's own re-authenticated disable / delete, the host-side
// recover-admin, and the two-person MFA reset. A new call site that clears a
// factor outside those flows is a takeover primitive (clear the factor, keep
// the password), so this guard allowlists the callers and fails on any other.
//
// What it recognises: any selector expression named DeleteMFAForUser or
// DeleteWebAuthnCredential (a call, or a method value); a call of a selector
// named SetUserMFAEnabled or SetUserWebAuthnEnabled whose last argument is not
// the identifier true (false, or any value the scan cannot prove is true), and a
// method value of either (callee "SetUserMFAEnabled(false)"); and an assignment
// to a selector named MFAEnabled or WebAuthnEnabled of anything but true (callee
// "MFAEnabled=false"). All in non-test .go files anywhere in the repository,
// keyed by file and enclosing top-level function. The
// core method KeyorixCore.DeleteWebAuthnCredential and its HTTP handler share the
// storage method's name and are listed as callers too, so a second route to the
// self-service delete has to be named here as well.
//
// What it does not see: a call through reflection, a method value stored under
// another name, a raw SQL DELETE of mfa_secrets / mfa_recovery_codes /
// webauthn_credentials or UPDATE of users.mfa_enabled / webauthn_enabled (the
// storage layer's own setter is one: internal/storage/store's
// SetUserMFAEnabled writes the column through gorm's Update), a composite literal
// that builds a user with MFAEnabled: false (every user creation does, so it is
// not a clearer signal), and a row whose flag was read false and written back
// over a concurrent enable (a stale full-row UpdateUser: no assignment to see).
// The storage layer's own definitions and the generated or
// delegating wrappers of the Storage interface (internal/faultstorage,
// storagetest) forward every method by construction and are skipped by
// directory.
//
// It reports through guardrules.Rollout: report-only on pull requests while
// docs/guard-rollout.d/TestEverySecondFactorClearerCallerIsAllowlisted.tsv
// exists (docs/guard-rollout-contract.md rule 2). The red proof is
// TestSecondFactorClearerGuard_RejectsAnUnlistedCallSite, which runs the same
// scan over a fixture package under testdata and does not go through Rollout.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

var (
	secondFactorClearers = []string{"DeleteMFAForUser", "DeleteWebAuthnCredential"}
	// secondFactorFlagSetters clear a factor when called with anything but true.
	secondFactorFlagSetters = []string{"SetUserMFAEnabled", "SetUserWebAuthnEnabled"}
	// secondFactorFlagFields clear a factor when assigned anything but true.
	secondFactorFlagFields = []string{"MFAEnabled", "WebAuthnEnabled"}
)

func isIdentTrue(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "true"
}

// The walk does not enter a directory with one of these names anywhere in the
// tree, nor one of these repo-relative paths. web/ holds no Go; tmp/ is a session
// workspace (sandboxed sessions keep exports there).
var (
	secondFactorSkipNames = []string{".git", ".scratch", "node_modules", "testdata"}
	secondFactorSkipPaths = []string{"web", "tmp", "internal/faultstorage", "internal/core/storage/storagetest"}
)

// allowedSecondFactorClearerSites: "repo-relative file:enclosing function|callee"
// ("Type.Method" for methods) -> why this site may clear a factor.
var allowedSecondFactorClearerSites = map[string]string{
	"internal/core/mfa.go:KeyorixCore.DisableMFA|DeleteMFAForUser":                                   "self-service disable: needs the user's current TOTP code or password",
	"internal/core/webauthn.go:KeyorixCore.DeleteWebAuthnCredential|DeleteWebAuthnCredential":        "self-service passkey delete: needs the user's code or password",
	"server/http/handlers/webauthn.go:AuthHandler.DeleteWebAuthnCredential|DeleteWebAuthnCredential": "HTTP route of the self-service passkey delete; it passes the user's proof to the core method above",
	"server/http/router.go:NewRouter|DeleteWebAuthnCredential":                                       "route registration of the handler above (a method value, not a call); blocked while impersonating",
	"internal/core/mfa_reset_effect.go:ResetMFACredentialsInTx|DeleteMFAForUser":                     "the shared full credential reset: two-person online flow and host reset-mfa",
	"internal/core/mfa_reset_effect.go:ResetMFACredentialsInTx|DeleteWebAuthnCredential":             "same reset, WebAuthn half",
	"server/admin/recover_admin_logic.go:performRecoverAdminWithTTL|DeleteMFAForUser":                "host-side recover-admin (recovery key, server stopped)",
	"server/admin/recover_admin_logic.go:performRecoverAdminWithTTL|DeleteWebAuthnCredential":        "same recover-admin, WebAuthn half",
	// #3801 (b): the flag setters with false.
	"internal/core/mfa.go:KeyorixCore.DisableMFA|SetUserMFAEnabled(false)":                         "self-service disable, the flag half of the DeleteMFAForUser entry above",
	"internal/core/webauthn.go:KeyorixCore.DeleteWebAuthnCredential|SetUserWebAuthnEnabled(false)": "self-service passkey delete: the flag goes off with the user's last passkey",
	"internal/core/mfa_reset_effect.go:ResetMFACredentialsInTx|SetUserMFAEnabled(false)":           "the shared full credential reset, TOTP flag",
	"internal/core/mfa_reset_effect.go:ResetMFACredentialsInTx|SetUserWebAuthnEnabled(false)":      "the shared full credential reset, WebAuthn flag",
	"server/admin/recover_admin_logic.go:performRecoverAdminWithTTL|SetUserMFAEnabled(false)":      "host-side recover-admin, TOTP flag",
	"server/admin/recover_admin_logic.go:performRecoverAdminWithTTL|SetUserWebAuthnEnabled(false)": "host-side recover-admin, WebAuthn flag",
}

func secondFactorFuncKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// scanSecondFactorClearers returns every "file:func|callee" site under root.
// skipNames and skipPaths are the directories to leave out (see the vars above;
// the fixture scan passes none).
func scanSecondFactorClearers(t testing.TB, root string, skipNames, skipPaths []string) []string {
	t.Helper()
	seen := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (slices.Contains(skipPaths, rel) || slices.Contains(skipNames, d.Name()) || strings.HasPrefix(d.Name(), ".redproof-")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", rel, perr)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			site := rel + ":" + secondFactorFuncKey(fd) + "|"
			// Setter selectors that are the callee of a call are judged by their
			// argument there; any other use of one is a method value.
			called := map[*ast.SelectorExpr]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok && slices.Contains(secondFactorFlagSetters, sel.Sel.Name) {
						called[sel] = true
						if len(n.Args) == 0 || !isIdentTrue(n.Args[len(n.Args)-1]) {
							seen[site+sel.Sel.Name+"(false)"] = true
						}
					}
				case *ast.SelectorExpr:
					if slices.Contains(secondFactorClearers, n.Sel.Name) {
						seen[site+n.Sel.Name] = true
					}
					if slices.Contains(secondFactorFlagSetters, n.Sel.Name) && !called[n] {
						seen[site+n.Sel.Name+"(false)"] = true
					}
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || !slices.Contains(secondFactorFlagFields, sel.Sel.Name) {
							continue
						}
						if len(n.Rhs) != len(n.Lhs) || !isIdentTrue(n.Rhs[i]) {
							seen[site+sel.Sel.Name+"=false"] = true
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unlistedSecondFactorClearers returns the sites not in allow.
func unlistedSecondFactorClearers(sites []string, allow map[string]string) []string {
	var out []string
	for _, s := range sites {
		if _, ok := allow[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

func TestEverySecondFactorClearerCallerIsAllowlisted(t *testing.T) {
	g := guardrules.Rollout(t)
	sites := scanSecondFactorClearers(t, srcpath.RepoRoot(), secondFactorSkipNames, secondFactorSkipPaths)
	for _, s := range unlistedSecondFactorClearers(sites, allowedSecondFactorClearerSites) {
		g.Errorf("%s clears a second factor but is not an allowed caller: route it through the two-person reset (core.ResetMFACredentialsInTx) or the user's own re-authenticated disable/delete, or add it to allowedSecondFactorClearerSites with the reason it is safe (docs/design/recovery-options.md section 1)", s)
	}
	for key := range allowedSecondFactorClearerSites {
		if !slices.Contains(sites, key) {
			g.Errorf("allowedSecondFactorClearerSites has %q, which no longer exists: remove the entry", key)
		}
	}
}

// Red proof: the scan over a fixture package that holds an unlisted call site (a
// test double's method and a handler-shaped function) reports both, and a
// fixture of only allowlisted shapes reports none. Not routed through Rollout, so
// it stays blocking while the real guard is report-only.
func TestSecondFactorClearerGuard_RejectsAnUnlistedCallSite(t *testing.T) {
	fixtures := filepath.Join(srcpath.PkgDir(), "testdata", "secondfactor")

	bad := scanSecondFactorClearers(t, filepath.Join(fixtures, "bad"), nil, nil)
	got := unlistedSecondFactorClearers(bad, allowedSecondFactorClearerSites)
	want := []string{
		"clearer.go:BackdoorStore.WipeFactors|DeleteMFAForUser",
		"clearer.go:BackdoorStore.WipeFactors|DeleteWebAuthnCredential",
		"clearer.go:quietReset|DeleteMFAForUser",
		"flags.go:flagFromInput|SetUserMFAEnabled(false)",
		"flags.go:flagsOff|SetUserMFAEnabled(false)",
		"flags.go:flagsOff|SetUserWebAuthnEnabled(false)",
		"flags.go:fullRowClear|MFAEnabled=false",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("guard did not reject the fixture's unlisted call sites:\n got  %q\n want %q", got, want)
	}

	// Green: the one site of the good fixture is accepted once it is listed, and
	// the function without a call is not reported at all.
	good := scanSecondFactorClearers(t, filepath.Join(fixtures, "good"), nil, nil)
	if !slices.Equal(good, []string{"clearer.go:allowedReset|DeleteMFAForUser"}) {
		t.Fatalf("good fixture sites = %q", good)
	}
	allow := map[string]string{"clearer.go:allowedReset|DeleteMFAForUser": "fixture"}
	if extra := unlistedSecondFactorClearers(good, allow); len(extra) != 0 {
		t.Fatalf("allowlisted fixture site was rejected: %q", extra)
	}
	if unlisted := unlistedSecondFactorClearers(good, nil); len(unlisted) != 1 {
		t.Fatalf("without the entry the good fixture must be rejected, got %q", unlisted)
	}
}
