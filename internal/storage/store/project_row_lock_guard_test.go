package store

// project_row_lock_guard_test.go — the default-ci half of #2723/#2724, and the
// only leg of it that runs without a DSN.
//
// The defect was not a missing lock. deleteProjectCascade HAD a FOR UPDATE on the
// project row (added by #2656) — written with GORM's default scope, which appends
// `deleted_at IS NULL`. On an already-deleted project that matched zero rows and
// locked nothing, which is exactly the case where a concurrent RestoreProject has
// to be excluded. A lock with no row to take is not a lock, and nothing in the
// suite noticed, because the statement was present and syntactically a lock.
//
// So this guard checks the thing that was actually wrong: that the locking read
// on each side is UNSCOPED. A guard that merely asserted "takes clause.Locking"
// would have been green throughout the entire lifetime of the bug.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// projectRowLockers are the two sides that must exclude each other on the
// project row, and the function in each where the lock is taken.
//
// Why these two and no others: the pair that can produce the forbidden state is
// (a) anything that soft-deletes the project and sweeps its children, and (b)
// anything that un-deletes them. (a) is deleteProjectCascade — DeleteProject and
// DeleteProjectIfEmpty both delegate to it, which is why it was factored out
// (#528), so locking there covers both entry points. (b) is RestoreProject.
// RestoreEnvironment and RestoreSecret are single-child restores that already
// re-check the project through lockLiveParent (#2656, #2702) and are covered by
// their own guards; they never touch the project row's own deleted_at.
var projectRowLockers = []struct{ fn, note string }{
	{"lockProjectRowForCascade", "deleteProjectCascade's lock, shared by DeleteProject and DeleteProjectIfEmpty"},
	{"RestoreProject", "the restore side, which locks the project row before any child UPDATE"},
}

func TestProjectRowLocks_AreUnscoped(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "local_secrets.go", nil, 0)
	require.NoError(t, err)

	for _, l := range projectRowLockers {
		fd := prFindFunc(t, f, l.fn)
		locking, unscoped := prLockShape(fd)
		require.True(t, locking,
			"%s (%s) no longer takes clause.Locking on the project row — without it the two sides do not "+
				"exclude each other at all (#2723/#2724)", l.fn, l.note)
		require.True(t, unscoped,
			"%s (%s) takes a lock WITHOUT Unscoped() — GORM then appends `deleted_at IS NULL`, so on an "+
				"already-deleted project the lock matches zero rows and locks nothing. That is the original "+
				"#2723 defect verbatim: the statement is present and looks like a lock, and takes none "+
				"precisely in the case it exists for", l.fn, l.note)
	}
}

// TestDeleteProjectEntryPointsGoThroughTheSharedCascade pins the premise the
// list above rests on: that locking inside deleteProjectCascade covers both
// delete entry points. If one ever grew its own cascade, this guard's coverage
// claim would silently become false for that path.
func TestDeleteProjectEntryPointsGoThroughTheSharedCascade(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "local_secrets.go", nil, 0)
	require.NoError(t, err)
	for _, entry := range []string{"DeleteProject", "DeleteProjectIfEmpty"} {
		calls := prCallNames(prFindFunc(t, f, entry).Body)
		require.Contains(t, calls, "deleteProjectCascade",
			"LocalStorage.%s must delegate to deleteProjectCascade — TestProjectRowLocks_AreUnscoped only "+
				"covers this entry point through that shared function (#528, #2723)", entry)
	}
}

// prLockShape reports whether fd's body contains a clause.Locking call, and
// whether an Unscoped() call appears in the same function. Scoped to one
// function body, so an Unscoped() elsewhere in the file cannot satisfy it.
func prLockShape(fd *ast.FuncDecl) (locking, unscoped bool) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "Unscoped":
				unscoped = true
			case "Clauses":
				for _, a := range ce.Args {
					if cl, ok := a.(*ast.CompositeLit); ok {
						if sl, ok := cl.Type.(*ast.SelectorExpr); ok && sl.Sel.Name == "Locking" {
							locking = true
						}
					}
				}
			}
		}
		return true
	})
	return locking, unscoped
}

func prFindFunc(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name && fd.Body != nil {
			return fd
		}
	}
	t.Fatalf("local_secrets.go: %s not found — the guard's subject was renamed or moved; update the guard", name)
	return nil
}

func prCallNames(b *ast.BlockStmt) []string {
	var names []string
	ast.Inspect(b, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := ce.Fun.(type) {
		case *ast.Ident:
			names = append(names, fun.Name)
		case *ast.SelectorExpr:
			names = append(names, fun.Sel.Name)
		}
		return true
	})
	return names
}
