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

	for _, target := range []string{"backfillBlankAccountState", "guardAccountStateValid"} {
		if !callAbortsOnError(migrateDatabaseDecl, target) {
			t.Errorf("migrateDatabase's call to %s(...) must be wired as "+
				"`if err := %s(db); err != nil { return ... }` -- a failure here must abort "+
				"migrateDatabase, not be logged/ignored and continued past", target, target)
		}
	}
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
