// constant_time_guard_test.go — structural guard for Verify's constant-time comparison.
//
// Verify compares computed and stored SHA-256 hex digests using
// subtle.ConstantTimeCompare (design §6's adversarial-review checklist item,
// doc comment in recoverykey.go).  A short-circuiting == or bytes.Equal here
// would be a timing oracle: given a stored hash in hand, an attacker could
// submit candidate keys and observe which hex prefix first matches, narrowing
// the search at a rate of one nibble per round-trip.
//
// This guard verifies two properties of the Verify function statically:
//
//  1. PRESENT: a call to ConstantTimeCompare qualified by the file's
//     "crypto/subtle" import appears at least once in the body.
//  2. ABSENT:  no call to Equal qualified by the file's "bytes" import (or a
//     bare Equal under a dot-import of "bytes") appears anywhere in the body,
//     whether or not ConstantTimeCompare is also present.  hmac.Equal is not
//     flagged.
//
// Calls are matched through the file's import table, so an aliased import is
// still caught.  TestVerifyGuard_CheckerFlagsBytesEqual runs the checker over
// inline fixture sources and proves it goes red on bytes.Equal next to
// subtle.ConstantTimeCompare and stays green on hmac.Equal.
//
// (string == on the hex string values IS theoretically possible and would also
// be timing-sensitive; that check is not done here because == appears on
// non-secret things too and an AST scan without type resolution produces too
// many false positives.  The design comment and design §6's checklist are the
// human-readable guards for that form.)
package recoverykey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// parseGuardFile parses path, or src when it is non-nil.
func parseGuardFile(t *testing.T, path string, src any) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return f
}

// funcBody returns the body of funcName in f.  Fatals if the function is not
// found or has no body.
func funcBody(t *testing.T, f *ast.File, path, funcName string) *ast.BlockStmt {
	t.Helper()
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			if fd.Body == nil {
				t.Fatalf("%s has no body", funcName)
			}
			return fd.Body
		}
	}
	t.Fatalf("%s not found in %s — rename? update this guard", funcName, path)
	return nil
}

// qualifiedCalls counts the calls to importPath's function fn inside body,
// resolving the qualifier through f's import table: pkg.fn() for a plain or
// aliased import, bare fn() for a dot-import.  A file that does not import
// importPath has no such calls.
func qualifiedCalls(f *ast.File, body *ast.BlockStmt, importPath, defaultName, fn string) int {
	local := ""
	for _, spec := range f.Imports {
		if p, err := strconv.Unquote(spec.Path.Value); err == nil && p == importPath {
			local = defaultName
			if spec.Name != nil {
				local = spec.Name.Name
			}
			break
		}
	}
	if local == "" || local == "_" {
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

// comparisonCalls returns the number of subtle.ConstantTimeCompare and
// bytes.Equal calls in funcName's body.
func comparisonCalls(t *testing.T, f *ast.File, path, funcName string) (constantTime, bytesEqual int) {
	t.Helper()
	body := funcBody(t, f, path, funcName)
	return qualifiedCalls(f, body, "crypto/subtle", "subtle", "ConstantTimeCompare"),
		qualifiedCalls(f, body, "bytes", "bytes", "Equal")
}

// TestVerify_UsesConstantTimeCompare verifies that the Verify function calls
// subtle.ConstantTimeCompare to compare the computed and stored hex digests.
// A missing call means the comparison has been replaced with a variable-time
// primitive, turning Verify into a timing oracle for key-prefix matching.
func TestVerify_UsesConstantTimeCompare(t *testing.T) {
	t.Parallel()
	if ct, _ := comparisonCalls(t, parseGuardFile(t, "recoverykey.go", nil), "recoverykey.go", "Verify"); ct == 0 {
		t.Error("Verify does not call subtle.ConstantTimeCompare — the hex-digest comparison\n" +
			"must use a constant-time primitive (recoverykey.go doc comment, design §6's\n" +
			"adversarial-review checklist item)")
	}
}

// TestVerify_DoesNotUseBytesEqual verifies that the Verify function does not
// call bytes.Equal anywhere in its body, even next to subtle.ConstantTimeCompare
// (a variable-time early-out beside the constant-time compare is still an
// oracle).  hmac.Equal is constant-time and is not flagged.
func TestVerify_DoesNotUseBytesEqual(t *testing.T) {
	t.Parallel()
	if _, be := comparisonCalls(t, parseGuardFile(t, "recoverykey.go", nil), "recoverykey.go", "Verify"); be > 0 {
		t.Errorf("Verify calls bytes.Equal %d time(s) — the hex-digest comparison must use\n"+
			"subtle.ConstantTimeCompare only, never a variable-time primitive.\n"+
			"(recoverykey.go doc comment, design §6's adversarial-review checklist item)", be)
	}
}

// TestVerifyGuard_CheckerFlagsBytesEqual proves the checker both ways on
// inline fixture sources: red on bytes.Equal beside subtle.ConstantTimeCompare
// (plain and aliased import), green on hmac.Equal.
func TestVerifyGuard_CheckerFlagsBytesEqual(t *testing.T) {
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
func Verify(a, b []byte) bool { return bytes.Equal(a, b) || subtle.ConstantTimeCompare(a, b) == 1 }`,
			wantCT: 1, wantBE: 1,
		},
		{
			name: "aliased bytes import",
			src: `package x
import (bb "bytes"; "crypto/subtle")
func Verify(a, b []byte) bool { return bb.Equal(a, b) && subtle.ConstantTimeCompare(a, b) == 1 }`,
			wantCT: 1, wantBE: 1,
		},
		{
			name: "hmac.Equal is not bytes.Equal",
			src: `package x
import ("crypto/hmac"; "crypto/subtle")
func Verify(a, b []byte) bool { return hmac.Equal(a, b) && subtle.ConstantTimeCompare(a, b) == 1 }`,
			wantCT: 1, wantBE: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ct, be := comparisonCalls(t, parseGuardFile(t, "inline-fixture", tc.src), "inline-fixture", "Verify")
			if ct != tc.wantCT || be != tc.wantBE {
				t.Errorf("checker counted ConstantTimeCompare=%d bytes.Equal=%d, want %d and %d",
					ct, be, tc.wantCT, tc.wantBE)
			}
		})
	}
}
