// account_state_fatal_migration_guard_test.go — a structural guard, in the
// same family as server/http's raw_storage_bypass_guard_test.go, proving
// migrateDatabase's calls to backfillBlankAccountState and
// guardAccountStateValid are wired so a failure aborts migrateDatabase
// itself (`if err := X(db); err != nil { return ... }`), not merely logged
// and continued past.
//
// This is the actual enforcement of "fail closed on migration state": this
// codebase has no separate migration-ledger table to check at startup --
// migrateDatabase already runs synchronously, on every boot, before storage
// becomes usable, and its caller chain (createLocalStorage/
// createPostgresStorage -> CreateStorage -> server/main.go's log.Fatalf) is
// already fatal on any error migrateDatabase returns (confirmed by direct
// reading of factory.go:359-361, factory.go:382-384, and server/main.go's
// call site, which panics the process via log.Fatalf, itself calling
// os.Exit -- not independently re-provable in a unit test without killing
// the test binary). The one link in that chain this repo CAN keep honest via
// CI is this one: that migrateDatabase's own body never starts silently
// swallowing one of these two calls' errors. If it ever did, a real
// migration failure (e.g. the pre-existing-garbage-row case
// TestGuardAccountStateValid_Postgres_FailsLoudlyOnPreexistingGarbageRow
// covers) would leave migrateDatabase reporting success while the schema
// invariant it's supposed to guarantee silently didn't hold.
package storage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestMigrateDatabase_AccountStateCallsAbortOnError(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "factory.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing factory.go: %v", err)
	}

	var migrateDatabaseDecl *ast.FuncDecl
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name.Name == "migrateDatabase" {
			migrateDatabaseDecl = fd
			break
		}
	}
	if migrateDatabaseDecl == nil {
		t.Fatal("could not find migrateDatabase's declaration in factory.go")
	}

	targets := []string{"backfillBlankAccountState", "guardAccountStateValid"}
	var calledAtAll int
	for _, target := range targets {
		if bodyCallsFunction(migrateDatabaseDecl.Body, target) {
			calledAtAll++
		}
		if !callAbortsOnError(migrateDatabaseDecl, target) {
			t.Errorf("migrateDatabase's call to %s(...) must be wired as "+
				"`if err := %s(db); err != nil { return ... }` -- a failure here must abort "+
				"migrateDatabase, not be logged/ignored and continued past", target, target)
		}
	}
	// Distinct from the per-target abort-shape check above: if NEITHER target is
	// even called anywhere in migrateDatabase's body, the two t.Errorf calls above
	// would still fire (so this specific scenario isn't actually silent) -- but this
	// makes the "both were found at all" signal explicit and independently
	// verifiable, rather than inferred from the abort-shape check's own failure
	// message, which is worded for "wrong shape," not "absent entirely."
	if calledAtAll == 0 {
		t.Fatal("neither backfillBlankAccountState nor guardAccountStateValid is called " +
			"anywhere in migrateDatabase's body — this guard is now vacuous and is no longer " +
			"checking anything; fix the scan, not this assertion")
	}
}

// bodyCallsFunction reports whether body contains a call expression to a
// bare (unqualified) function named target, anywhere -- regardless of
// whether that call is wired to abort on error. Weaker than
// callAbortsOnError on purpose: it answers "is this even still called,"
// independent of "is it called correctly."
func bodyCallsFunction(body *ast.BlockStmt, target string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == target {
			found = true
		}
		return true
	})
	return found
}

// callAbortsOnError reports whether fd's body contains an if-statement of the
// shape `if err := <target>(...); err != nil { <block containing a return> }`.
func callAbortsOnError(fd *ast.FuncDecl, target string) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		assign, ok := ifStmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != target {
			return true
		}
		// Confirm the if's condition checks err != nil (the assigned variable).
		cond, ok := ifStmt.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return true
		}
		// Confirm the if-body contains a return statement (aborts the function)
		// rather than e.g. only a log call.
		hasReturn := false
		ast.Inspect(ifStmt.Body, func(bn ast.Node) bool {
			if _, ok := bn.(*ast.ReturnStmt); ok {
				hasReturn = true
			}
			return true
		})
		if hasReturn {
			found = true
		}
		return true
	})
	return found
}

// TestAccountStateMigrationScannerDetectsSwallowedErrors is this guard's
// red-proof.
//
// TestMigrateDatabase_AccountStateCallsAbortOnError asserts that today's
// factory.go is wired correctly. It cannot tell you whether callAbortsOnError
// would notice if factory.go stopped being wired correctly — and that
// distinction is the whole point of the guard, because the defect it exists
// to catch (an error logged and continued past rather than returned) looks
// exactly like working code.
//
// So: three functions, one correct and two defective in the two ways this
// actually goes wrong in practice, run through the real matcher.
func TestAccountStateMigrationScannerDetectsSwallowedErrors(t *testing.T) {
	// Parsed, never compiled.
	const src = `package fixture

func aborts(db *gorm.DB) error {
	if err := guardAccountStateValid(db); err != nil {
		return err
	}
	return nil
}

func swallowsWithLog(db *gorm.DB) error {
	if err := guardAccountStateValid(db); err != nil {
		log.Printf("account state guard failed: %v", err)
	}
	return nil
}

func neverChecks(db *gorm.DB) error {
	guardAccountStateValid(db)
	return nil
}
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "migration_fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the synthetic fixture: %v", err)
	}

	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			funcs[fd.Name.Name] = fd
		}
	}
	for _, want := range []string{"aborts", "swallowsWithLog", "neverChecks"} {
		if funcs[want] == nil {
			t.Fatalf("fixture is missing %s — the parse silently produced nothing to check", want)
		}
	}

	const target = "guardAccountStateValid"

	// bodyCallsFunction is the "is it called at all" half. All three call it;
	// if this stops being true the second half below is meaningless.
	for name, fd := range funcs {
		if !bodyCallsFunction(fd.Body, target) {
			t.Errorf("bodyCallsFunction failed to see the %s call in %s() — the call-detection half of "+
				"this guard has stopped working, which would make the abort check vacuous", target, name)
		}
	}

	// callAbortsOnError is the half that carries the actual invariant.
	if !callAbortsOnError(funcs["aborts"], target) {
		t.Errorf("callAbortsOnError must recognize the correct `if err := %s(db); err != nil { return err }` "+
			"shape. It does not, so the guard would now fail against correct code — and the natural way to "+
			"make CI green again is to weaken the guard.", target)
	}
	if callAbortsOnError(funcs["swallowsWithLog"], target) {
		t.Errorf("callAbortsOnError accepted a call whose error is logged and then continued past. That is " +
			"precisely the defect this guard exists to catch: migrateDatabase would report success while the " +
			"schema invariant silently did not hold.")
	}
	if callAbortsOnError(funcs["neverChecks"], target) {
		t.Errorf("callAbortsOnError accepted a call whose error is never checked at all")
	}
}
