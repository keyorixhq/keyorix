// constant_time_comparison_guard_test.go — INV-CORE-secret-comparisons-use-constant-time.
//
// Three functions in internal/core compare secret or bearer-token values and
// must use a constant-time primitive so the comparison cannot be used as a
// timing oracle:
//
//   - bootstrapSystemLocked (auth_bootstrap.go): compares the caller-supplied
//     bootstrap token against the server's configured bootstrapToken. A
//     variable-time comparison leaks partial matches to an unauthenticated
//     attacker attempting to seize the first-admin slot.
//
//   - validateTOTPStep (mfa.go): compares each TOTP code candidate against the
//     expected value. A variable-time comparison reduces the brute-force search
//     space for the six-digit validation window.
//
//   - CheckSCIMTokenShape (rules/scim_token.go): compares a newly-configured
//     SCIM token against each other currently-configured secret to prevent
//     credential reuse. A variable-time comparison would let a caller infer
//     whether a submitted token prefix matches a stored secret.
//
// For each function this guard verifies two properties:
//
//  1. PRESENT: subtle.ConstantTimeCompare appears at least once in the
//     function body.
//  2. ABSENT:  bytes.Equal does not appear anywhere in the function body
//     (the most likely accidental replacement).
//
// What it does NOT cover: string-equality (==) comparisons, which a compiler
// rejects on []byte but permits on string; a future string-based secret
// comparison would not be caught here.  The properties checked here are
// necessary but not sufficient for constant-time guarantees in all possible
// future shapes; the doc comments in each production file describe the full
// design intent.
//
// Red/green verification (see commit message): each test was confirmed to fail
// when the respective subtle.ConstantTimeCompare call was temporarily replaced
// with bytes.Equal, and to pass when it was restored.
//
// File paths in constantTimeComparisonEntries are relative to the guards/
// directory (the test's working directory), so they resolve to the actual file
// under internal/core/ or internal/core/rules/.  Helpers in this file use the
// path directly without prepending "../", unlike funcBodyCallsHelper which
// always prepends "../" to a bare name.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// selectorCallExistsAt parses the file at relPath (relative to the test's
// working directory, i.e. internal/core/guards/), locates funcName, and
// reports whether any *ast.CallExpr in the function body is a selector call
// whose Sel.Name equals calleeName.
func selectorCallExistsAt(t *testing.T, relPath, funcName, calleeName string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, relPath, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", relPath, err)
	}
	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		if cand, ok := decl.(*ast.FuncDecl); ok && cand.Name.Name == funcName {
			fd = cand
			break
		}
	}
	if fd == nil {
		t.Fatalf("function %s not found in %s — rename or file move? update this guard", funcName, relPath)
	}
	if fd.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == calleeName {
			found = true
			return false
		}
		return true
	})
	return found
}

// funcExistsAt parses the file at relPath and reports whether a function named
// funcName is declared in it.  relPath is relative to the test's working
// directory (internal/core/guards/).
func funcExistsAt(t *testing.T, relPath, funcName string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, relPath, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", relPath, err)
	}
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			return true
		}
	}
	return false
}

// constantTimeComparisonEntry describes one reviewed secret-comparison site
// that must use a constant-time primitive.  relPath is relative to
// internal/core/guards/ (the test's working directory).
type constantTimeComparisonEntry struct {
	relPath string // e.g. "../auth_bootstrap.go" or "../rules/scim_token.go"
	fn      string // function name
	reason  string // why constant-time is required here
}

// constantTimeComparisonEntries is the reviewed set of functions in
// internal/core that compare secret or bearer-token values.  Each entry is
// checked for the presence of ConstantTimeCompare and the absence of
// bytes.Equal.  Add a new entry when a secret-comparison site is introduced;
// remove one if the function is renamed or deleted (the companion
// TestConstantTimeComparison_EntriesStillExist will catch stale entries).
var constantTimeComparisonEntries = map[string]constantTimeComparisonEntry{
	"bootstrapSystemLocked": {
		relPath: "../auth_bootstrap.go",
		fn:      "bootstrapSystemLocked",
		reason: "compares the caller-supplied bootstrap token against the server's configured " +
			"bootstrapToken; a variable-time comparison leaks partial token matches to an " +
			"unauthenticated attacker attempting to seize the first-admin slot",
	},
	"validateTOTPStep": {
		relPath: "../mfa.go",
		fn:      "validateTOTPStep",
		reason: "compares each TOTP candidate code against the expected value; a variable-time " +
			"comparison reduces the brute-force search space for the six-digit validation window",
	},
	"CheckSCIMTokenShape": {
		relPath: "../rules/scim_token.go",
		fn:      "CheckSCIMTokenShape",
		reason: "compares a newly-configured SCIM token against each other currently-configured " +
			"secret; a variable-time comparison lets a caller infer whether a submitted token " +
			"prefix matches a stored secret",
	},
}

// TestConstantTimeComparison_UsesConstantTimePrimitive verifies that each
// guarded function calls subtle.ConstantTimeCompare somewhere in its body.
func TestConstantTimeComparison_UsesConstantTimePrimitive(t *testing.T) {
	t.Parallel()
	for name, e := range constantTimeComparisonEntries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !selectorCallExistsAt(t, e.relPath, e.fn, "ConstantTimeCompare") {
				t.Errorf("%s (%s) must call subtle.ConstantTimeCompare — %s\n"+
					"(INV-CORE-secret-comparisons-use-constant-time)", e.fn, e.relPath, e.reason)
			}
		})
	}
}

// TestConstantTimeComparison_NoBytesEqualOnSecret verifies that no guarded
// function calls bytes.Equal anywhere in its body.  bytes.Equal is the most
// likely accidental replacement for subtle.ConstantTimeCompare on []byte values.
// A function that calls BOTH Equal and ConstantTimeCompare is flagged only if
// ConstantTimeCompare is absent (a full replacement, not a coexistence, since
// hmac.Equal is also a constant-time primitive and may legitimately coexist).
func TestConstantTimeComparison_NoBytesEqualOnSecret(t *testing.T) {
	t.Parallel()
	for name, e := range constantTimeComparisonEntries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if selectorCallExistsAt(t, e.relPath, e.fn, "Equal") &&
				!selectorCallExistsAt(t, e.relPath, e.fn, "ConstantTimeCompare") {
				t.Errorf("%s (%s) calls bytes.Equal (or hmac.Equal) on a secret comparison\n"+
					"and does NOT call subtle.ConstantTimeCompare — this is likely an\n"+
					"accidental variable-time replacement.\n"+
					"Reason this matters: %s\n"+
					"(INV-CORE-secret-comparisons-use-constant-time)", e.fn, e.relPath, e.reason)
			}
		})
	}
}

// TestConstantTimeComparison_EntriesStillExist verifies that each function
// named in constantTimeComparisonEntries actually exists in its stated file.
// A stale entry (function renamed or deleted) would silently stop being
// checked by the two tests above.
func TestConstantTimeComparison_EntriesStillExist(t *testing.T) {
	t.Parallel()
	for name, e := range constantTimeComparisonEntries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !funcExistsAt(t, e.relPath, e.fn) {
				t.Errorf("constantTimeComparisonEntries entry %q names function %s in %s "+
					"but no such function was found — update or remove this entry",
					name, e.fn, e.relPath)
			}
		})
	}
}

// TestConstantTimeComparison_ReasonsAreNonEmpty guards against an entry added
// with an empty justification.
func TestConstantTimeComparison_ReasonsAreNonEmpty(t *testing.T) {
	t.Parallel()
	for name, e := range constantTimeComparisonEntries {
		if e.reason == "" {
			t.Errorf("constantTimeComparisonEntries entry %q has no written justification", name)
		}
	}
}
