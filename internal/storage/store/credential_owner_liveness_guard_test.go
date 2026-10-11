package store

// credential_owner_liveness_guard_test.go — the default-ci half of #2701, so the
// fix is guarded in the DSN-less CI leg too (the two
// TestCTAReview_Create{PAT,Session}_vs_SuspendUser_CrossReplicaPostgres tests in
// internal/core are the behavioural proof and need real Postgres).
//
// It lives here, not in internal/core, because the subjects are
// internal/storage/store functions and internal/core's AST helpers are scoped to
// files under internal/core.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCredentialInsertsRecheckOwnerLiveness asserts that each of the three
// credential-row inserts a suspend/deactivate/delete sweep is supposed to cover
// re-checks its owner inside the SAME transaction, and that the shared re-check
// actually goes through lockLiveParent.
//
// The three are named explicitly, and that list is the guard's own weak point,
// so here is how it was derived rather than asserted: the sweep paths revoke
// exactly two tables — personal_access_tokens
// (RevokeAllPersonalAccessTokensForUser) and sessions
// (DeleteSessionsForUserExcept) — so the population is every LocalStorage method
// that INSERTs into one of those two. A grep for `tx.Create(`/`.Create(` against
// models.PersonalAccessToken and models.Session in this package yields exactly
// CreatePersonalAccessToken, CreateSession and RotateSession. A fourth insert
// into either table would not be caught by this test; it would be caught by the
// pg tests only if someone wrote one, which is why the derivation is written
// down here instead of left implicit.
func TestCredentialInsertsRecheckOwnerLiveness(t *testing.T) {
	for _, fn := range []string{"CreatePersonalAccessToken", "CreateSession", "RotateSession"} {
		calls := credGuardCalls(t, "local_auth.go", "LocalStorage", fn)
		require.Contains(t, calls, "Transaction",
			"%s must do its insert inside a transaction — the owner re-check is only sound if it shares "+
				"one with the INSERT (#2701)", fn)
		require.Contains(t, calls, "requireLiveCredentialOwner",
			"%s must re-check its owning user's liveness after the insert; without it the credential "+
				"commits after a suspend/deactivate/delete sweep that was audited as complete (#2701)", fn)
	}

	// And the shared re-check must be the real row-locking one, not a plain read:
	// a bare SELECT does not serialize against the sweep's own row lock.
	shared := credGuardCalls(t, "local_auth.go", "", "requireLiveCredentialOwner")
	require.Contains(t, shared, "lockLiveParent",
		"requireLiveCredentialOwner must go through lockLiveParent (SELECT ... FOR SHARE on Postgres) — "+
			"an unlocked re-read would not serialize against the sweep's LockUserForUpdate (#2701)")
}

// credGuardCalls returns the names of every function/method call in the named
// function's body. recvType "" matches a plain function.
func credGuardCalls(t *testing.T, file, recvType, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
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
		var names []string
		ast.Inspect(fd.Body, func(n ast.Node) bool {
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
	t.Fatalf("%s: function %s (receiver %q) not found — the guard's subject was renamed; update the guard", file, name, recvType)
	return nil
}
