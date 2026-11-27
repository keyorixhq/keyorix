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
//     must each call kdfmeter.CompareHashAndPassword(*dummyBcryptHash.Load(), ...).
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
//     requireReauth (mfa.go), the step-up re-auth path, has the same pair of
//     branches and the same expected count.
//
// The count checks are deterministic: they count identifiers or call-selector
// sites in the parsed function body.  For sites 1 and 2,
// TestTimingEqualization_EveryPreCompareEarlyReturnSpendsDummy also checks
// position: every top-level if-block that returns before the real comparison
// must reference dummyBcryptHash before its first return, so moving both
// dummy calls into one block fails.  Red/green verification (see the PR body):
// each property test was confirmed to fail on an out-of-tree mutation of the
// production file and to pass on the unmodified file.
//
// What these tests do NOT verify: the position of the recordFailedLogin calls
// in site 3 (a count of 2 would not catch both calls moved into one branch);
// an early return nested inside a non-if statement (for, switch) before the
// real comparison.  The INVARIANTS.d fragments and in-source comments pin
// those.
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

// teEarlyReturnBlock is one top-level if-block that returns before the real
// password comparison.
type teEarlyReturnBlock struct {
	line           int  // line of the if statement
	dummyBeforeRet bool // a dummyBcryptHash reference precedes the block's first return
}

// teEarlyReturnBlocks parses file (relative to ../), walks funcName's
// top-level statements up to the first one that calls CompareHashAndPassword
// without referencing dummyBcryptHash (the real comparison), and returns every
// if statement before it whose body contains a return. Fatals when no real
// comparison is found, so the walk cannot pass on an empty prefix.
func teEarlyReturnBlocks(t *testing.T, file, funcName string) []teEarlyReturnBlock {
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
	if fd == nil || fd.Body == nil {
		t.Fatalf("function %s not found in %s — rename or file move? update this guard", funcName, file)
	}
	firstDummy := func(n ast.Node) token.Pos {
		pos := token.NoPos
		ast.Inspect(n, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok && id.Name == "dummyBcryptHash" && (pos == token.NoPos || id.Pos() < pos) {
				pos = id.Pos()
			}
			return true
		})
		return pos
	}
	realCompare := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CompareHashAndPassword" && firstDummy(call) == token.NoPos {
				found = true
			}
			return !found
		})
		return found
	}
	var blocks []teEarlyReturnBlock
	for _, st := range fd.Body.List {
		if realCompare(st) {
			return blocks
		}
		ifs, ok := st.(*ast.IfStmt)
		if !ok {
			continue
		}
		firstRet := token.NoPos
		ast.Inspect(ifs.Body, func(m ast.Node) bool {
			if r, ok := m.(*ast.ReturnStmt); ok && (firstRet == token.NoPos || r.Pos() < firstRet) {
				firstRet = r.Pos()
			}
			return true
		})
		if firstRet == token.NoPos {
			continue
		}
		d := firstDummy(ifs.Body)
		blocks = append(blocks, teEarlyReturnBlock{
			line:           fset.Position(ifs.Pos()).Line,
			dummyBeforeRet: d != token.NoPos && d < firstRet,
		})
	}
	t.Fatalf("%s in %s has no top-level CompareHashAndPassword call on a real hash — update this guard", funcName, file)
	return nil
}

// TestTimingEqualization_EveryPreCompareEarlyReturnSpendsDummy guards the
// position half of INV-CORE-password-login-timing-equalization that the
// counts above cannot see: EVERY top-level if-block that returns before the
// real CompareHashAndPassword call must reference dummyBcryptHash before its
// first return. Moving both dummy calls into one block, or adding a new early
// return without one, fails here. The wantBlocks count keeps the walk from
// passing on a refactor that hides the early returns from it.
func TestTimingEqualization_EveryPreCompareEarlyReturnSpendsDummy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file, fn   string
		wantBlocks int
	}{
		{"auth.go", "VerifyPasswordCredentials", 2},
		{"account.go", "verifyCurrentPassword", 1},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			t.Parallel()
			blocks := teEarlyReturnBlocks(t, tc.file, tc.fn)
			if len(blocks) != tc.wantBlocks {
				t.Errorf("%s has %d early-return if-block(s) before the real comparison, want %d — "+
					"review the new path and update this guard (INV-CORE-password-login-timing-equalization)",
					tc.fn, len(blocks), tc.wantBlocks)
			}
			for _, b := range blocks {
				if !b.dummyBeforeRet {
					t.Errorf("%s:%d: early-return block in %s returns before spending the dummy bcrypt "+
						"comparison — its latency differs from a wrong password "+
						"(INV-CORE-password-login-timing-equalization)", tc.file, b.line, tc.fn)
				}
			}
		})
	}
}

// TestTimingEqualization_RequireReauthPostVerdictFailureCountsTowardLockout
// guards the requireReauth sibling of
// INV-CORE-mfa-replay-consume-fail-counts-lockout: the step-up re-auth path
// has the same pair of failure branches (the code/password matched but a
// consumption write failed; the code/password was wrong), and both must call
// recordFailedLogin so a correct guess is never cheaper, lockout-wise, than a
// wrong one (#2888).
func TestTimingEqualization_RequireReauthPostVerdictFailureCountsTowardLockout(t *testing.T) {
	t.Parallel()
	const want = 2
	got := countFuncBodySelectorCalls(t, "mfa.go", "requireReauth", "recordFailedLogin")
	if got != want {
		t.Errorf("requireReauth has %d recordFailedLogin call(s), want %d: once in the\n"+
			"postVerdictErr branch (credential correct, consumption write failed) and once\n"+
			"in the wrong-credential path (#2888, INV-CORE-mfa-replay-consume-fail-counts-lockout)",
			got, want)
	}
}
