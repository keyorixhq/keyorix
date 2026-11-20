// timing_equalization_guard_test.go — INV-CORE-password-login-timing-equalization
// and INV-CORE-mfa-replay-consume-fail-counts-lockout structural guards.
//
// Three login-path sites explicitly spend extra work so an observer cannot
// distinguish negative outcomes by latency:
//
//  1. VerifyPasswordCredentials (auth.go): a missing username and a locked
//     account must each take as long as a wrong password, so an attacker
//     cannot enumerate accounts by timing.  The function's two pre-bcrypt
//     early-return if-blocks (user-not-found/storage-error; loginLocked)
//     must each call bcrypt.CompareHashAndPassword(*dummyBcryptHash.Load(), ...).
//     Expected count: 2 references to dummyBcryptHash in the function body.
//
//  2. verifyCurrentPassword (account.go): the same locked-account oracle
//     exists on the self-service credential-change endpoint; it spends one
//     dummy bcrypt call in the loginLocked branch.
//     Expected count: 1 reference to dummyBcryptHash in the function body.
//
//  3. VerifyMFACredentials (mfa.go): when the submitted TOTP code WAS correct
//     but the anti-replay MarkTOTPStepUsed write then failed, the lockout
//     counter must still be incremented — otherwise the timing difference
//     between "code correct, write failed" and "code wrong" becomes a side
//     channel confirming correctness even though the returned error and HTTP
//     response are identical (#2888).  The function therefore calls
//     recordFailedLogin in that branch as well as the normal wrong-code one.
//     Expected count: 2 calls to recordFailedLogin in the function body.
//
// Each check is deterministic: it counts identifiers or call-selector sites
// in the parsed function body.  Red/green verification (see commit message):
// each test was confirmed to fail when the respective call was temporarily
// commented out and to pass with it restored.
//
// What these tests do NOT verify: that the calls are in the correct positions
// relative to their respective return statements (a count of 2 would not
// catch both calls being moved into the same block).  That ordering property
// is pinned by the INVARIANTS.d fragments and by the in-source comments.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// countFuncBodyIdent parses file (relative to ../), finds the top-level or
// method declaration named funcName, and returns the number of *ast.Ident
// nodes whose Name equals identName anywhere in the function body.
// Matching is by identifier name only (no type resolution); dummyBcryptHash
// appears in production code exclusively in its timing-equalization role, so
// an ident count is a sufficient structural proxy.
func countFuncBodyIdent(t *testing.T, file, funcName, identName string) int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../"+file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		if cand, ok := decl.(*ast.FuncDecl); ok && cand.Name.Name == funcName {
			fd = cand
			break
		}
	}
	if fd == nil {
		t.Fatalf("function %s not found in %s — rename or file move? update this guard", funcName, file)
	}
	if fd.Body == nil {
		return 0
	}
	count := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == identName {
			count++
		}
		return true
	})
	return count
}

// countFuncBodySelectorCalls parses file, finds funcName, and returns the
// number of *ast.CallExpr nodes whose callee is a *ast.SelectorExpr with
// Sel.Name == calleeName.  This matches both c.foo() and pkg.foo() shapes,
// but not bare foo() calls; that is intentional: recordFailedLogin is always
// called as c.recordFailedLogin in this codebase.
func countFuncBodySelectorCalls(t *testing.T, file, funcName, calleeName string) int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../"+file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		if cand, ok := decl.(*ast.FuncDecl); ok && cand.Name.Name == funcName {
			fd = cand
			break
		}
	}
	if fd == nil {
		t.Fatalf("function %s not found in %s — rename or file move? update this guard", funcName, file)
	}
	if fd.Body == nil {
		return 0
	}
	count := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == calleeName {
			count++
		}
		return true
	})
	return count
}

// TestTimingEqualization_VerifyPasswordCredentials_DummyBcryptOnPreRealBcryptPaths
// guards INV-CORE-password-login-timing-equalization for VerifyPasswordCredentials.
//
// Expected: 2 dummyBcryptHash references — one inside the if-block that handles
// a GetUserByUsername error (covers both "no such user" and "storage error", since
// both return from that same block), and one inside the loginLocked if-block.
// A count below 2 means at least one early-return path no longer spends the dummy
// bcrypt comparison and can be distinguished from a wrong-password response by
// latency alone.
func TestTimingEqualization_VerifyPasswordCredentials_DummyBcryptOnPreRealBcryptPaths(t *testing.T) {
	t.Parallel()
	const (
		want = 2
		desc = "VerifyPasswordCredentials needs 2 dummyBcryptHash.Load() calls: one in\n" +
			"the user-not-found/storage-error block (line ~54) and one in the loginLocked\n" +
			"block (line ~73). Each pre-real-bcrypt early-return path must cost the same as\n" +
			"a wrong-password path to prevent account-enumeration timing side-channels.\n" +
			"(INV-CORE-password-login-timing-equalization)"
	)
	got := countFuncBodyIdent(t, "auth.go", "VerifyPasswordCredentials", "dummyBcryptHash")
	if got != want {
		t.Errorf("VerifyPasswordCredentials has %d dummyBcryptHash reference(s), want %d\n%s", got, want, desc)
	}
}

// TestTimingEqualization_VerifyCurrentPassword_DummyBcryptOnLockedPath guards
// INV-CORE-password-login-timing-equalization for verifyCurrentPassword.
//
// Expected: 1 dummyBcryptHash reference — inside the loginLocked block.  The
// self-service credential-change endpoint carries the same locked-account
// timing-oracle risk as the login endpoint.
func TestTimingEqualization_VerifyCurrentPassword_DummyBcryptOnLockedPath(t *testing.T) {
	t.Parallel()
	const (
		want = 1
		desc = "verifyCurrentPassword needs 1 dummyBcryptHash.Load() call in its\n" +
			"loginLocked block so a locked-account response costs the same as a\n" +
			"wrong-password response (account.go comment, INV-CORE-password-login-timing-equalization)"
	)
	got := countFuncBodyIdent(t, "account.go", "verifyCurrentPassword", "dummyBcryptHash")
	if got != want {
		t.Errorf("verifyCurrentPassword has %d dummyBcryptHash reference(s), want %d\n%s", got, want, desc)
	}
}

// TestTimingEqualization_MFACodeMatchedStorageError_CountsTowardLockout guards
// INV-CORE-mfa-replay-consume-fail-counts-lockout.
//
// Expected: 2 recordFailedLogin calls in VerifyMFACredentials — once in the
// codeMatched+storageErr branch (the TOTP code was confirmed correct, but the
// anti-replay MarkTOTPStepUsed write failed) and once in the normal wrong-code
// path.  Without the first call, the lockout counter becomes a timing side
// channel confirming code correctness even though the error and HTTP response
// are identical on both paths (#2888).
func TestTimingEqualization_MFACodeMatchedStorageError_CountsTowardLockout(t *testing.T) {
	t.Parallel()
	const (
		want = 2
		desc = "VerifyMFACredentials needs 2 recordFailedLogin calls: once in the\n" +
			"codeMatched+storageErr branch (code correct, anti-replay write failed) and\n" +
			"once in the normal wrong-code path, so the lockout counter cannot be used\n" +
			"as a side channel confirming code correctness (#2888,\n" +
			"INV-CORE-mfa-replay-consume-fail-counts-lockout)"
	)
	got := countFuncBodySelectorCalls(t, "mfa.go", "VerifyMFACredentials", "recordFailedLogin")
	if got != want {
		t.Errorf("VerifyMFACredentials has %d recordFailedLogin call(s), want %d\n%s", got, want, desc)
	}
}
