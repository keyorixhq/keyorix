package guards

// update_secret_column_scoped_guard_test.go — the default-ci half of #2695, so
// the fix is guarded in the DSN-less CI leg too (the three
// TestCTAReview_*_CrossReplicaPostgres tests are the behavioural proof and need
// real Postgres).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUpdateSecretWrites_AreColumnScoped checks the storage body and every one of
// the eight call sites #2695 moved. Naming all eight is the point: the defect
// lived in the shared primitive, so a guard covering only the one the issue
// titles would leave seven live.
func TestUpdateSecretWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_secrets.go", "UpdateSecretFields")

	for _, c := range []struct{ file, fn string }{
		{"classification.go", "ClassifySecret"},
		{"secret_description.go", "SetSecretDescription"},
		{"secret_ownership.go", "transferOwnership"},
		{"secret_move.go", "MoveSecret"},
		{"secret_bulk_rename.go", "BulkRenameSecrets"},
		{"secret_extend_expiring.go", "ExtendExpiringSecrets"},
		{"secrets.go", "UpdateSecret"},
		{"secrets_versions.go", "updateSecretWithNewVersion"},
	} {
		// updateSecretWithNewVersion, transferOwnership (#3102: the owner write and
		// the share re-stamp share one transaction) and UpdateSecret (AUDIT-MUTATION-TX-1:
		// the field write and its audit row share one transaction) write through their
		// transaction handle, so the required receiver is "tx" there and "storage"
		// everywhere else.
		recv := "storage"
		if c.fn == "updateSecretWithNewVersion" || c.fn == "transferOwnership" || c.fn == "UpdateSecret" {
			recv = "tx"
		}
		assertCoreWritesOnlyVia(t, "../"+c.file, c.fn, recv, "UpdateSecretFields", "Save", "UpdateSecret")
	}
}

// TestUpdateSecretRequest_FieldSetsMatch is the guard the comment on
// secretFieldUpdateFromRequest promises, rather than a comment asking the next
// reader to keep two functions in step by hand.
//
// applyUpdateSecretFields mutates the in-memory struct (for the value returned
// to the caller, and for the new-version path); secretFieldUpdateFromRequest
// names the columns that may actually be written. If a field is added to
// UpdateSecretRequest and wired into only the first, the API appears to accept
// it and silently never persists it. If only into the second, the returned
// object disagrees with the row. Both are silent, so this compares the set of
// `req.<Field>` reads in the two bodies.
func TestUpdateSecretRequest_FieldSetsMatch(t *testing.T) {
	apply := reqFieldsRead(t, "../secrets.go", "applyUpdateSecretFields")
	derive := reqFieldsRead(t, "../secrets.go", "secretFieldUpdateFromRequest")
	require.NotEmpty(t, apply, "sanity: applyUpdateSecretFields must read at least one request field")
	require.Equal(t, apply, derive,
		"applyUpdateSecretFields and secretFieldUpdateFromRequest must read the SAME UpdateSecretRequest "+
			"fields — a field wired into only one of them is either accepted-and-never-persisted or "+
			"persisted-but-not-reflected in the returned object, both silently (#2695)")
}

// reqFieldsRead returns the sorted set of `req.<Field>` selector names read in
// the named function's body.
func reqFieldsRead(t *testing.T, file, fn string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "req" {
				seen[sel.Sel.Name] = true
			}
			return true
		})
		out := make([]string, 0, len(seen))
		for k := range seen {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	t.Fatalf("%s: function %s not found — the guard's subject was renamed; update the guard", file, fn)
	return nil
}
