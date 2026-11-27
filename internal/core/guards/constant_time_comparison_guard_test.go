// constant_time_comparison_guard_test.go — INV-CORE-secret-comparisons-use-constant-time.
//
// A reviewed subset of internal/core functions compare secret or bearer-token
// values and must use a constant-time primitive so the comparison cannot be
// used as a timing oracle:
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
//   - rotateSecret (secrets.go): compares the decrypted current secret value
//     against the rotation's new value for no-op detection. A variable-time
//     comparison leaks a prefix match against live secret material.
//
// For each function this guard verifies two properties:
//
//  1. PRESENT: a call to ConstantTimeCompare qualified by the file's
//     "crypto/subtle" import appears at least once in the function body.
//  2. ABSENT:  no call to Equal qualified by the file's "bytes" import (or a
//     bare Equal under a dot-import of "bytes") appears anywhere in the
//     function body, whether or not ConstantTimeCompare is also present.
//     hmac.Equal and time.Time.Equal are not flagged.
//
// Calls are matched through the file's import table, so an aliased import
// (`b "bytes"`) is still caught. TestConstantTimeComparison_CheckerFlagsBytesEqual
// runs the checker over inline fixture sources and proves it goes red on
// bytes.Equal next to subtle.ConstantTimeCompare.
//
// What it does NOT cover: string-equality (==) comparisons, which a compiler
// rejects on []byte but permits on string; a future string-based secret
// comparison would not be caught here. The entry list is a reviewed subset,
// not derived: a new secret-comparison site in internal/core is checked only
// once it is added to constantTimeComparisonEntries. The properties checked
// here are necessary but not sufficient for constant-time guarantees in all
// possible future shapes; the doc comments in each production file describe
// the full design intent.
//
// File paths in constantTimeComparisonEntries are relative to the guards/
// directory (the test's working directory), so they resolve to the actual file
// under internal/core/ or internal/core/rules/.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// ctFuncInFile returns the declaration of funcName in f, or nil when no such
// function is declared.
func ctFuncInFile(f *ast.File, funcName string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			return fd
		}
	}
	return nil
}

// ctImportName returns the local name under which f imports importPath:
// the package's own last path element when unaliased, the alias when
// aliased, "." for a dot-import, and "" when f does not import it.
func ctImportName(f *ast.File, importPath, defaultName string) string {
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return defaultName
	}
	return ""
}

// ctQualifiedCalls counts the calls to importPath's function fn inside body,
// resolving the qualifier through f's import table: pkg.fn() for a plain or
// aliased import, bare fn() for a dot-import. A file that does not import
// importPath has no such calls.
func ctQualifiedCalls(f *ast.File, body *ast.BlockStmt, importPath, defaultName, fn string) int {
	local := ctImportName(f, importPath, defaultName)
	if local == "" || local == "_" || body == nil {
		return 0
	}
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if x, ok := fun.X.(*ast.Ident); ok && local != "." && x.Name == local && fun.Sel.Name == fn {
				count++
			}
		case *ast.Ident:
			if local == "." && fun.Name == fn {
				count++
			}
		}
		return true
	})
	return count
}

// ctComparisonCalls reports, for funcName in f, the number of
// subtle.ConstantTimeCompare calls and the number of bytes.Equal calls.
func ctComparisonCalls(t *testing.T, f *ast.File, path, funcName string) (constantTime, bytesEqual int) {
	t.Helper()
	fd := ctFuncInFile(f, funcName)
	if fd == nil {
		t.Fatalf("function %s not found in %s — rename or file move? update this guard", funcName, path)
	}
	return ctQualifiedCalls(f, fd.Body, "crypto/subtle", "subtle", "ConstantTimeCompare"),
		ctQualifiedCalls(f, fd.Body, "bytes", "bytes", "Equal")
}

// ctParse parses the file at relPath (relative to internal/core/guards/), or
// src when it is non-nil.
func ctParse(t *testing.T, relPath string, src any) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), relPath, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", relPath, err)
	}
	return f
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
// checked for the presence of subtle.ConstantTimeCompare and the absence of
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
	"rotateSecret": {
		relPath: "../secrets.go",
		fn:      "rotateSecret",
		reason: "compares the decrypted current secret value against the rotation's new value " +
			"(no-op detection); a variable-time comparison leaks a prefix match against live " +
			"secret material",
	},
}

// TestConstantTimeComparison_UsesConstantTimePrimitive verifies that each
// guarded function calls subtle.ConstantTimeCompare somewhere in its body.
func TestConstantTimeComparison_UsesConstantTimePrimitive(t *testing.T) {
	t.Parallel()
	for name, e := range constantTimeComparisonEntries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ct, _ := ctComparisonCalls(t, ctParse(t, e.relPath, nil), e.relPath, e.fn)
			if ct == 0 {
				t.Errorf("%s (%s) must call subtle.ConstantTimeCompare — %s\n"+
					"(INV-CORE-secret-comparisons-use-constant-time)", e.fn, e.relPath, e.reason)
			}
		})
	}
}

// TestConstantTimeComparison_NoBytesEqualOnSecret verifies that no guarded
// function calls bytes.Equal anywhere in its body, even next to a
// subtle.ConstantTimeCompare call: a variable-time early-out added beside the
// constant-time comparison is as much an oracle as a full replacement.
// hmac.Equal (constant-time) and other Equal methods are not flagged.
func TestConstantTimeComparison_NoBytesEqualOnSecret(t *testing.T) {
	t.Parallel()
	for name, e := range constantTimeComparisonEntries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, be := ctComparisonCalls(t, ctParse(t, e.relPath, nil), e.relPath, e.fn); be > 0 {
				t.Errorf("%s (%s) calls bytes.Equal %d time(s) — a variable-time comparison on a\n"+
					"secret value, whether or not subtle.ConstantTimeCompare is also called.\n"+
					"Reason this matters: %s\n"+
					"(INV-CORE-secret-comparisons-use-constant-time)", e.fn, e.relPath, be, e.reason)
			}
		})
	}
}

// TestConstantTimeComparison_CheckerFlagsBytesEqual proves the checker both
// ways on inline fixture sources: red on bytes.Equal next to
// subtle.ConstantTimeCompare (the mutation the original Equal-and-not-
// ConstantTimeCompare condition let through), on an aliased and on a
// dot-imported bytes package; green on hmac.Equal and on a time.Time Equal
// method.
func TestConstantTimeComparison_CheckerFlagsBytesEqual(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		src            string
		wantCT, wantBE int
	}{
		{
			name: "bytes.Equal beside ConstantTimeCompare",
			src: `package x
import ("bytes"; "crypto/subtle")
func f(a, b string) bool {
	if !bytes.Equal([]byte(a), []byte(b)) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1 {
		return false
	}
	return true
}`,
			wantCT: 1, wantBE: 1,
		},
		{
			name: "aliased bytes import",
			src: `package x
import (b "bytes"; s "crypto/subtle")
func f(x, y []byte) bool { return b.Equal(x, y) || s.ConstantTimeCompare(x, y) == 1 }`,
			wantCT: 1, wantBE: 1,
		},
		{
			name: "dot-imported bytes",
			src: `package x
import (. "bytes"; "crypto/subtle")
func f(x, y []byte) bool { return Equal(x, y) && subtle.ConstantTimeCompare(x, y) == 1 }`,
			wantCT: 1, wantBE: 1,
		},
		{
			name: "hmac.Equal and time Equal are not bytes.Equal",
			src: `package x
import ("crypto/hmac"; "crypto/subtle"; "time")
func f(x, y []byte, t1, t2 time.Time) bool {
	return hmac.Equal(x, y) && t1.Equal(t2) && subtle.ConstantTimeCompare(x, y) == 1
}`,
			wantCT: 1, wantBE: 0,
		},
		{
			name: "local variable named subtle is not crypto/subtle",
			src: `package x
type cmp struct{}
func (cmp) ConstantTimeCompare(a, b []byte) int { return 1 }
func f(x, y []byte) bool { subtle := cmp{}; return subtle.ConstantTimeCompare(x, y) == 1 }`,
			wantCT: 0, wantBE: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ct, be := ctComparisonCalls(t, ctParse(t, "inline-fixture", tc.src), "inline-fixture", "f")
			if ct != tc.wantCT || be != tc.wantBE {
				t.Errorf("checker counted ConstantTimeCompare=%d bytes.Equal=%d, want %d and %d",
					ct, be, tc.wantCT, tc.wantBE)
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
			if ctFuncInFile(ctParse(t, e.relPath, nil), e.fn) == nil {
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
