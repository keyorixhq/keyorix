package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func readAuditBatchItem(eventType string, success *bool) *auditBatchItem {
	return &auditBatchItem{event: &models.AuditEvent{EventType: eventType, Success: success}}
}

// TestIsSQLiteNormalReadAuditBatch: only a batch whose EVERY row is a
// successful secret-value read audit may commit on the SQLite read-audit
// connection (ADR-112 Amendment 7). One other row anywhere in the batch, a
// denied read, a nil Success or an empty batch keeps it on FULL.
func TestIsSQLiteNormalReadAuditBatch(t *testing.T) {
	yes, no := true, false
	read := func() *auditBatchItem { return readAuditBatchItem("secret.read", &yes) }
	cases := []struct {
		name  string
		batch []*auditBatchItem
		want  bool
	}{
		{"one read", []*auditBatchItem{read()}, true},
		{"reads and federated reads", []*auditBatchItem{read(), readAuditBatchItem("connect.secret_read", &yes), read()}, true},
		{"empty", nil, false},
		{"mutation audit first", []*auditBatchItem{readAuditBatchItem("secret.updated", &yes), read()}, false},
		{"mutation audit last", []*auditBatchItem{read(), read(), readAuditBatchItem("secret.deleted", &yes)}, false},
		{"denied read", []*auditBatchItem{read(), readAuditBatchItem("secret.read", &no)}, false},
		{"nil success", []*auditBatchItem{readAuditBatchItem("secret.read", nil)}, false},
		{"metadata read", []*auditBatchItem{readAuditBatchItem("secret.metadata_read", &yes)}, false},
		{"nil event", []*auditBatchItem{{}}, false},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, isSQLiteNormalReadAuditBatch(tc.batch), tc.name)
	}
}

// TestAuditBatchDB_NoReadAuditDBMeansSharedPool: without a read-audit
// connection (strict, PostgreSQL, a transaction-scoped clone) every batch,
// read audits included, commits on the shared pool.
func TestAuditBatchDB_NoReadAuditDBMeansSharedPool(t *testing.T) {
	ls := &LocalStorage{}
	yes := true
	db, normal := ls.auditBatchDB([]*auditBatchItem{readAuditBatchItem("secret.read", &yes)})
	require.False(t, normal)
	require.Same(t, ls.db, db)
}

// TestSQLiteReadAuditDB_UsedOnlyByTheAuditBatchSelector is the structural half
// of INV-STORAGE-sqlite-normal-conn-read-audit-only: the NORMAL handle is
// reachable from exactly three functions -- its setter, Close, and
// auditBatchDB, the selector that hands it only to batches of successful read
// audits. Any other function that reads ls.sqliteReadAuditDB (a new query,
// a mutation, a clone that copies it) fails here, so a mutation cannot reach
// the NORMAL connection without this test being edited in review.
//
// What it does not see: a reflect- or unsafe-based access, or code outside
// this package (the field is unexported, so there is none).
func TestSQLiteReadAuditDB_UsedOnlyByTheAuditBatchSelector(t *testing.T) {
	allowed := []string{"SetSQLiteReadAuditDB", "Close", "auditBatchDB"}
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var users []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "sqliteReadAuditDB" {
					users = append(users, fn.Name.Name)
				}
				if kv, ok := n.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "sqliteReadAuditDB" {
						users = append(users, fn.Name.Name+" (composite literal)")
					}
				}
				return true
			})
		}
	}
	require.NotEmpty(t, users, "the scan found no use at all: it is not looking at this package's sources")
	for _, u := range users {
		require.True(t, slices.Contains(allowed, u),
			"%s uses sqliteReadAuditDB, the synchronous=NORMAL handle (ADR-112 Amendment 7). Only %v may: "+
				"every other transaction must stay on the FULL pool", u, allowed)
	}
	for _, a := range allowed {
		require.True(t, slices.Contains(users, a), "%s no longer uses sqliteReadAuditDB: update this test's allowlist", a)
	}
}
