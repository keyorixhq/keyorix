package guards

// project_child_liveness_guard_test.go — the default-ci half of #2702, #2710,
// #2711 and #2712, so the fix is guarded in the DSN-less CI leg too (the four
// TestCTAReview_*_vs_DeleteProject_CrossReplicaPostgres tests are the
// behavioural proof and need real Postgres).
//
// It asserts the shape, not the behaviour: each writer must do its child write
// inside a transaction closure and re-check the project (LockLiveProject or
// lockLiveParent) AFTER that write and INSIDE that same closure — write first,
// then check, which is what makes it sound (a cascade that runs entirely between
// a pre-write check and the write never sees the row; a check outside the
// closure shares no transaction with the write). LIVENESS-IN-TX-2's reviewer
// noted the first version only checked that the call exists somewhere in the
// writer; REVOKE-GUARDS-NOV-1 item 3 checks the placement.
//
// How placement is checked: the transaction closure is the function literal
// passed to WithTransaction / Transaction / mutationTx / withAuditedMutation
// whose own top-level statements contain the write call (not inside a nested
// function literal). The check must be a call in a LATER top-level statement of
// that same closure body, not inside a nested function literal, defer or go.
// What this does not check: control flow inside a statement (a check under an
// if that is false on some path, or an early return between the two), and the
// SQL the check runs (TestLockLiveProject_GoesThroughLockLiveParent pins the
// locking hop; the TestCTAReview_*_CrossReplicaPostgres tests are the
// behavioural proof).

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// projectChildWriters is every entry point that creates or revives a row whose
// parent is a project, together with where its project re-check must live.
//
// How this list was derived, rather than asserted: DeleteProject's cascade
// (deleteProjectCascade, internal/storage/store/local_secrets.go) sweeps exactly
// three child tables — secret_nodes, environments, and dynamic_secret_configs
// (disabled, not soft-deleted). So the population is every writer that can make
// a row in one of those three live while the project is being deleted:
//
//   - secret_nodes: core.CreateSecret, core.CreateFolder (both insert), and
//     LocalStorage.RestoreSecret (clears deleted_at). core.RestoreFolder does not
//     exist; folders are restored through RestoreSecret, the same SecretNode row.
//     core.ResumeSecret (#2794) flips status suspended -> active: DeleteEnvironment
//     counts only active secrets, so a suspended one is no barrier, and resuming
//     inside a deleted environment/project would leave a live secret under a dead
//     parent. It is not an insert or an un-delete, but it is the same
//     "make a swept row live" write.
//   - environments: core.CreateEnvironment (insert) and
//     LocalStorage.RestoreEnvironment (clears deleted_at — already fixed by
//     #2656 and included here so a regression there is caught by the same guard).
//     seedProjectEnvironment is excluded: it runs inside the transaction that
//     just created the project, so there is no deleted-parent window.
//   - dynamic_secret_configs: the cascade DISABLES rather than deletes, and
//     IssueLease/RenewLease refuse against a disabled config, so a config created
//     in the window is inert rather than live-under-a-dead-parent. Excluded
//     deliberately, not overlooked — if the cascade ever starts soft-deleting
//     them, CreateDynamicSecretConfig belongs on this list.
//
// RestoreProject itself is NOT here: it is the parent, and its own race with a
// re-issued DeleteProject is #2723/#2724, a different shape (the cascade's
// FOR UPDATE matches nothing when the project row is already deleted).
//
// write is the call name of the child write the re-check must follow.
var projectChildWriters = []struct {
	file, recvType, fn, write string
}{
	{"../secrets.go", "KeyorixCore", "CreateSecret", "CreateSecret"},
	{"../secrets.go", "KeyorixCore", "CreateFolder", "CreateSecret"},
	{"../secret_suspend.go", "KeyorixCore", "ResumeSecret", "TransitionSecretStatus"},
	{"../catalog.go", "KeyorixCore", "CreateEnvironment", "CreateEnvironment"},
	{"../../storage/store/local_secrets.go", "LocalStorage", "RestoreSecret", "Update"},
	{"../../storage/store/local_secrets.go", "LocalStorage", "RestoreEnvironment", "Update"},
}

// projectTxOpeners are the calls whose function-literal argument is a
// transaction closure: mutationTx / withAuditedMutation (AUDIT-TX-2,
// mutation_audit_tx.go) open the transaction themselves, plain or with the
// audit rows in it.
var projectTxOpeners = map[string]bool{
	"WithTransaction": true, "Transaction": true, "mutationTx": true, "withAuditedMutation": true,
}

// projectLivenessCheckNames are the two spellings of the re-check: the exported
// Storage method a core-layer caller uses, and the store-internal helper a
// LocalStorage method calls directly.
var projectLivenessCheckNames = map[string]bool{
	"LockLiveProject": true,
	"lockLiveParent":  true,
}

func TestProjectChildWrites_RecheckProjectLivenessInATransaction(t *testing.T) {
	for _, w := range projectChildWriters {
		_, fd := projectGuardFunc(t, w.file, w.recvType, w.fn)
		if msg := liveCheckPlacement(fd, w.write); msg != "" {
			t.Errorf("%s.%s: %s — the project re-check is only sound after the child write and in the same "+
				"transaction; deleteProjectCascade takes no named lock that would serialize them "+
				"(#2702/#2710/#2711/#2712)", w.recvType, w.fn, msg)
		}
	}
}

// liveCheckPlacement returns "" when fd's write call (by name) is a direct
// statement of a transaction closure and a project re-check is a direct, later
// statement of that same closure; otherwise what is wrong.
func liveCheckPlacement(fd *ast.FuncDecl, write string) string {
	var closures []*ast.FuncLit
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || !projectTxOpeners[callName(ce)] {
			return true
		}
		for _, a := range ce.Args {
			if fl, ok := a.(*ast.FuncLit); ok {
				closures = append(closures, fl)
			}
		}
		return true
	})
	if len(closures) == 0 {
		return "no transaction closure (WithTransaction/Transaction/mutationTx/withAuditedMutation)"
	}
	for _, cl := range closures {
		writeIdx := firstStmtCalling(cl.Body.List, func(name string) bool { return name == write })
		if writeIdx < 0 {
			continue
		}
		checkIdx := firstStmtCalling(cl.Body.List, func(name string) bool { return projectLivenessCheckNames[name] })
		switch {
		case checkIdx < 0:
			return fmt.Sprintf("no LockLiveProject/lockLiveParent in the transaction closure that does the %s write "+
				"(a re-check outside it shares no transaction with the write)", write)
		case checkIdx <= writeIdx:
			return fmt.Sprintf("the LockLiveProject/lockLiveParent re-check (statement %d of the closure) does not come "+
				"after the %s write (statement %d): a cascade that commits between them is never seen", checkIdx, write, writeIdx)
		}
		return ""
	}
	return fmt.Sprintf("the %s write is not a direct statement of any transaction closure", write)
}

// firstStmtCalling returns the index of the first statement in list that
// contains a call matching match, not counting calls inside a nested function
// literal or a defer/go statement (those do not run in statement order); -1 if
// none.
func firstStmtCalling(list []ast.Stmt, match func(string) bool) int {
	for i, st := range list {
		if _, ok := st.(*ast.DeferStmt); ok {
			continue
		}
		if _, ok := st.(*ast.GoStmt); ok {
			continue
		}
		found := false
		ast.Inspect(st, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				if match(callName(v)) {
					found = true
				}
			}
			return !found
		})
		if found {
			return i
		}
	}
	return -1
}

func callName(ce *ast.CallExpr) string {
	switch fun := ce.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// TestProjectChildWrites_PlacementCalibration mutates a copy of a real child
// write (CreateFolder, parsed from secrets.go) two ways and requires both to be
// red, and the unmutated copy green: the re-check moved BEFORE the write inside
// the closure, and the re-check moved OUT of the transaction closure (into the
// enclosing environment-guard callback, still under the named lock).
func TestProjectChildWrites_PlacementCalibration(t *testing.T) {
	const file, fn, write = "../secrets.go", "CreateFolder", "CreateSecret"
	parse := func(t *testing.T) (*token.FileSet, *ast.FuncDecl) {
		fset, fd := projectGuardFunc(t, file, "KeyorixCore", fn)
		return fset, fd
	}
	if _, fd := parse(t); liveCheckPlacement(fd, write) != "" {
		t.Fatalf("unmutated %s must be green, got %q", fn, liveCheckPlacement(fd, write))
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, fd *ast.FuncDecl)
		want   string
	}{
		{"lock_before_write", func(t *testing.T, fd *ast.FuncDecl) {
			cl := txClosureWithWrite(t, fd, write)
			w := firstStmtCalling(cl.Body.List, func(n string) bool { return n == write })
			block := cutCheckBlock(t, cl)
			cl.Body.List = append(cl.Body.List[:w:w], append(block, cl.Body.List[w:]...)...)
		}, "does not come after the CreateSecret write"},
		{"lock_outside_closure", func(t *testing.T, fd *ast.FuncDecl) {
			cl := txClosureWithWrite(t, fd, write)
			block := cutCheckBlock(t, cl)
			parent, idx := enclosingBlock(t, fd, cl)
			parent.List = append(parent.List[:idx:idx], append(block, parent.List[idx:]...)...)
		}, "no LockLiveProject/lockLiveParent in the transaction closure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset, fd := parse(t)
			tc.mutate(t, fd)
			var src bytes.Buffer
			if err := printer.Fprint(&src, fset, fd); err != nil {
				t.Fatal(err)
			}
			got := liveCheckPlacement(fd, write)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("mutated %s (%s) must be red with %q, got %q; mutated source:\n%s", fn, tc.name, tc.want, got, src.String())
			}
		})
	}
}

// txClosureWithWrite returns the transaction closure whose direct statements
// contain the write call.
func txClosureWithWrite(t *testing.T, fd *ast.FuncDecl, write string) *ast.FuncLit {
	t.Helper()
	var out *ast.FuncLit
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || !projectTxOpeners[callName(ce)] {
			return true
		}
		for _, a := range ce.Args {
			if fl, ok := a.(*ast.FuncLit); ok && firstStmtCalling(fl.Body.List, func(n string) bool { return n == write }) >= 0 {
				out = fl
			}
		}
		return true
	})
	if out == nil {
		t.Fatalf("%s: no transaction closure with a %s write", fd.Name.Name, write)
	}
	return out
}

// cutCheckBlock removes the re-check statement and the two error/liveness ifs
// after it from the closure and returns them.
func cutCheckBlock(t *testing.T, cl *ast.FuncLit) []ast.Stmt {
	t.Helper()
	i := firstStmtCalling(cl.Body.List, func(n string) bool { return projectLivenessCheckNames[n] })
	if i < 0 || i+3 > len(cl.Body.List) {
		t.Fatalf("closure has no re-check block to move (index %d of %d)", i, len(cl.Body.List))
	}
	block := append([]ast.Stmt(nil), cl.Body.List[i:i+3]...)
	cl.Body.List = append(cl.Body.List[:i:i], cl.Body.List[i+3:]...)
	return block
}

// enclosingBlock returns the innermost block of fd holding a statement that
// contains cl, and that statement's index.
func enclosingBlock(t *testing.T, fd *ast.FuncDecl, cl *ast.FuncLit) (*ast.BlockStmt, int) {
	t.Helper()
	var best *ast.BlockStmt
	bestIdx := -1
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		b, ok := n.(*ast.BlockStmt)
		if !ok || b == cl.Body {
			return true
		}
		for i, st := range b.List {
			if st.Pos() <= cl.Pos() && cl.End() <= st.End() {
				if best == nil || (b.Pos() >= best.Pos() && b.End() <= best.End()) {
					best, bestIdx = b, i
				}
			}
		}
		return true
	})
	if best == nil {
		t.Fatalf("%s: no block encloses the transaction closure", fd.Name.Name)
	}
	return best, bestIdx
}

// TestLockLiveProject_GoesThroughLockLiveParent pins the one hop the guard above
// relies on: LockLiveProject must be the row-locking helper, not a plain read.
// An unlocked re-read answers the same question and serializes against nothing.
func TestLockLiveProject_GoesThroughLockLiveParent(t *testing.T) {
	calls := projectGuardCalls(t, "../../storage/store/local_parent_liveness.go", "LocalStorage", "LockLiveProject")
	require.Contains(t, calls, "lockLiveParent",
		"LockLiveProject must go through lockLiveParent (SELECT ... FOR SHARE on Postgres) — a bare SELECT "+
			"would not serialize against deleteProjectCascade's FOR UPDATE on the project row")
}

// projectGuardFunc returns the named function's declaration (and its file
// set). Fails the test if the function is not found, so a rename turns the
// guard red rather than vacuous.
func projectGuardFunc(t *testing.T, file, recvType, name string) (*token.FileSet, *ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name || fd.Body == nil {
			continue
		}
		got := ""
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			x := fd.Recv.List[0].Type
			if st, ok := x.(*ast.StarExpr); ok {
				x = st.X
			}
			if id, ok := x.(*ast.Ident); ok {
				got = id.Name
			}
		}
		if got != recvType {
			continue
		}
		return fset, fd
	}
	t.Fatalf("%s: function %s (receiver %q) not found — the guard's subject was renamed or moved; update the guard", file, name, recvType)
	return nil, nil
}

// projectGuardCalls returns the names of every function/method call in the named
// function's body.
func projectGuardCalls(t *testing.T, file, recvType, name string) []string {
	t.Helper()
	_, fd := projectGuardFunc(t, file, recvType, name)
	var names []string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if ce, ok := n.(*ast.CallExpr); ok {
			if name := callName(ce); name != "" {
				names = append(names, name)
			}
		}
		return true
	})
	return names
}
