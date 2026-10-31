package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCreateShareRecord_IsColumnScoped is the create-side guard for #2648's class
// (#2801, #2802, LEASE-SHARE-RACE-1). createShareRecordTx's two upsert paths, the
// re-share of an existing live share and the fallback after losing the #136 create
// race, used to persist the row they had read with GORM Save: a resurrection
// primitive when a revoke commits between the read and the write, and the fallback
// also dropped the caller's ExpiresAt. Both now go through ONE helper,
// reshareOntoLiveRow, whose only write is applyShareRequest's conditional,
// column-scoped UPDATE.
//
// Hops checked: createShareRecordTx calls reshareOntoLiveRow on both paths and
// writes no Save/Select("*") itself; reshareOntoLiveRow writes no Save/Select("*");
// applyShareRequest is Where + Updates and no Save. The race itself is proved by
// internal/storage/store/local_sharing_create_race_test.go (SQLite and Postgres).
//
// Not covered: a write reached through a helper other than these three (the
// storage package's TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels
// catches any Save on ShareRecord in that package, which has no exemption row for
// createShareRecordTx any more).
func TestCreateShareRecord_IsColumnScoped(t *testing.T) {
	const store = "../../storage/store/local_sharing.go"
	for _, fn := range []string{"createShareRecordTx", "reshareOntoLiveRow", "applyShareRequest"} {
		for _, c := range columnScopedFuncCalls(t, store, "", fn) {
			if c.Name == "Save" {
				t.Errorf("%s: %s calls %s.Save, a full-row upsert that resurrects a concurrently revoked share", store, fn, c.Recv)
			}
			if c.Name == "Select" {
				t.Errorf("%s: %s calls Select, the share upsert must name its columns in the Updates map", store, fn)
			}
		}
	}
	var where, updates bool
	for _, c := range columnScopedFuncCalls(t, store, "", "applyShareRequest") {
		switch c.Name {
		case "Where":
			where = true
		case "Updates", "UpdateColumns":
			updates = true
		}
	}
	if !where || !updates {
		t.Errorf("%s: applyShareRequest no longer issues a conditional column-scoped UPDATE (Where=%v, Updates=%v)", store, where, updates)
	}
	if n := countPlainCalls(t, store, "createShareRecordTx", "reshareOntoLiveRow"); n != 2 {
		t.Errorf("%s: createShareRecordTx calls reshareOntoLiveRow %d times, want 2 (the re-share path and the lost-race fallback share one write)", store, n)
	}
	if n := countPlainCalls(t, store, "reshareOntoLiveRow", "applyShareRequest"); n != 1 {
		t.Errorf("%s: reshareOntoLiveRow calls applyShareRequest %d times, want 1", store, n)
	}
}

// countPlainCalls counts calls written as a bare identifier `callee(...)` inside the
// plain function fn in path (columnScopedFuncCalls only sees selector calls).
func countPlainCalls(t *testing.T, path, fn, callee string) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		n := 0
		ast.Inspect(fd.Body, func(node ast.Node) bool {
			if ce, ok := node.(*ast.CallExpr); ok {
				if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == callee {
					n++
				}
			}
			return true
		})
		return n
	}
	t.Fatalf("%s: function %s not found; the guard's subject was renamed or moved", path, fn)
	return 0
}
