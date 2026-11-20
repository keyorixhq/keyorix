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
//  1. PRESENT: subtle.ConstantTimeCompare appears at least once in the body.
//  2. ABSENT:  bytes.Equal does not appear anywhere in the body.
//
// (string == on the hex string values IS theoretically possible and would also
// be timing-sensitive; that check is not done here because == appears on
// non-secret things too and an AST scan without type resolution produces too
// many false positives.  The design comment and design §6's checklist are the
// human-readable guards for that form.)
//
// Red/green verification (see commit message): temporarily replacing
// subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1 with
// bytes.Equal([]byte(computed), []byte(storedHash)) in recoverykey.go made
// TestVerify_UsesConstantTimeCompare fail ("ConstantTimeCompare not found")
// and TestVerify_DoesNotUseBytesEqual fail ("bytes.Equal found") at the same
// time; restoring the original made both pass.
package recoverykey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// verifyFuncBody parses recoverykey.go, finds the Verify function, and returns
// its body for inspection.  Fatals if the file cannot be parsed or the function
// is not found.
func verifyFuncBody(t *testing.T) *ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "recoverykey.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing recoverykey.go: %v", err)
	}
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "Verify" {
			if fd.Body == nil {
				t.Fatal("Verify has no body")
			}
			return fd.Body
		}
	}
	t.Fatal("Verify not found in recoverykey.go — rename? update this guard")
	return nil
}

// selectorCallExistsInBody reports whether any *ast.CallExpr in body is a
// selector call whose Sel.Name equals calleeName.
func selectorCallExistsInBody(body *ast.BlockStmt, calleeName string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
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

// TestVerify_UsesConstantTimeCompare verifies that the Verify function calls
// subtle.ConstantTimeCompare to compare the computed and stored hex digests.
// A missing call means the comparison has been replaced with a variable-time
// primitive, turning Verify into a timing oracle for key-prefix matching.
func TestVerify_UsesConstantTimeCompare(t *testing.T) {
	t.Parallel()
	body := verifyFuncBody(t)
	if !selectorCallExistsInBody(body, "ConstantTimeCompare") {
		t.Error("Verify does not call subtle.ConstantTimeCompare — the hex-digest comparison\n" +
			"must use a constant-time primitive (recoverykey.go doc comment, design §6's\n" +
			"adversarial-review checklist item)")
	}
}

// TestVerify_DoesNotUseBytesEqual verifies that the Verify function does not
// call bytes.Equal anywhere in its body.  bytes.Equal is the most likely
// accidental replacement for subtle.ConstantTimeCompare on []byte comparisons.
func TestVerify_DoesNotUseBytesEqual(t *testing.T) {
	t.Parallel()
	body := verifyFuncBody(t)
	if selectorCallExistsInBody(body, "Equal") {
		t.Error("Verify calls bytes.Equal (or hmac.Equal) — the hex-digest comparison\n" +
			"must use subtle.ConstantTimeCompare, not any variable-time primitive.\n" +
			"(recoverykey.go doc comment, design §6's adversarial-review checklist item)")
	}
}
