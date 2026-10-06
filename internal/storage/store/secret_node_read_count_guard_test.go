// secret_node_read_count_guard_test.go — #2843: a full-struct write of a
// SecretNode must never carry read_count.
//
// read_count is the lifetime counter behind MaxReads, advanced only by a
// conditional SQL expression so concurrent readers cannot overshoot the cap
// (TryIncrementSecretNodeReadCount, #133). A full-struct Save()/Updates()
// re-sends whatever read_count the caller loaded, so an UNRELATED metadata edit
// silently refunds reads against the cap — see secretNodeSQLOwnedColumns' doc
// comment in local_secrets.go for the interleaving.
//
// Two site patches would not have been the fix: EVERY UpdateSecret caller in
// internal/core has the load-mutate-save shape, and the next storage method to
// write a SecretNode struct would reintroduce it. So this file holds the
// invariant (the AST/type guard) alongside the two behavioural red/green tests
// that prove the invariant is about something real.
//
// # What the guard recognises, and what it does not
//
// Per CLAUDE.md's "an enumeration is only as complete as the idioms it knows
// about", the recognised shape is stated here rather than left implicit:
//
//   - RECOGNISED: any call to .Save / .Updates / .UpdateColumns anywhere in
//     package store where at least one argument's STATIC TYPE unwraps to
//     models.SecretNode (bare, pointer, slice, or map value). Type information,
//     not names, so a value that reaches the call through a field selector or a
//     helper's return still counts.
//   - NOT RECOGNISED, deliberately: .Updates(map[string]any{...}). A map write
//     names its columns explicitly, so including "read_count" there is a
//     deliberate act by someone who typed the column name, not the accidental
//     carry-along this guard exists to stop. Zero such writes to secret_nodes
//     exist today (grep: the only map-form Updates in this package target other
//     tables).
//   - NOT RECOGNISED, deliberately: .Create / .FirstOrCreate. An INSERT must
//     carry read_count — a new row's counter is part of the row.
//   - NOT RECOGNISED: raw db.Exec SQL. Nothing in this package UPDATEs
//     secret_nodes via raw SQL (the one raw statement that touches the table is
//     the cache_epoch migration's DDL), and a hand-written UPDATE naming
//     read_count is again deliberate rather than accidental.
//   - SCOPE: package store only. Every gorm write in this repo lives here —
//     internal/core and the handlers go through the storage.Storage interface,
//     which has no method that takes a *gorm.DB.
package store

import (
	"context"
	"go/ast"
	"go/types"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fullStructWriteMethods are the gorm methods that build an UPDATE's SET list
// from a struct's fields rather than from column names the caller typed out.
var fullStructWriteMethods = map[string]bool{
	"Save":          true,
	"Updates":       true,
	"UpdateColumns": true,
}

const secretNodeTypeFullName = "github.com/keyorixhq/keyorix/internal/storage/models.SecretNode"

func unwrapToNamedForReadCountGuard(t types.Type) *types.Named {
	for {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Slice:
			t = x.Elem()
		case *types.Array:
			t = x.Elem()
		case *types.Map:
			t = x.Elem()
		case *types.Named:
			return x
		default:
			return nil
		}
	}
}

// chainOmitsSQLOwnedColumns walks the method chain to the LEFT of the write
// call looking for .Omit(secretNodeSQLOwnedColumns...).
//
// It requires that exact identifier, not just any Omit: an Omit("read_count")
// written as a literal at one site would pass a looser check while leaving the
// NEXT column added to secretNodeSQLOwnedColumns uncovered at that site. One
// list, referenced everywhere, is the point.
func chainOmitsSQLOwnedColumns(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	for expr := sel.X; ; {
		inner, ok := expr.(*ast.CallExpr)
		if !ok {
			return false
		}
		innerSel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if innerSel.Sel.Name == "Omit" {
			for _, arg := range inner.Args {
				if id, ok := arg.(*ast.Ident); ok && id.Name == "secretNodeSQLOwnedColumns" {
					return true
				}
			}
		}
		expr = innerSel.X
	}
}

// TestNoFullStructWriteOfASecretNodeCarriesReadCount type-checks package store
// and fails on any Save/Updates/UpdateColumns of a SecretNode value whose chain
// does not omit secretNodeSQLOwnedColumns.
func TestNoFullStructWriteOfASecretNodeCarriesReadCount(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Dir:  ".",
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("package failed to type-check")
	}
	require.Len(t, pkgs, 1)
	pkg := pkgs[0]

	var violations []string
	var checked int
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !fullStructWriteMethods[sel.Sel.Name] {
				return true
			}
			writesASecretNode := false
			for _, arg := range call.Args {
				tv := pkg.TypesInfo.TypeOf(arg)
				if tv == nil {
					continue
				}
				named := unwrapToNamedForReadCountGuard(tv)
				if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
					continue
				}
				if named.Obj().Pkg().Path()+"."+named.Obj().Name() == secretNodeTypeFullName {
					writesASecretNode = true
				}
			}
			if !writesASecretNode {
				return true
			}
			checked++
			if !chainOmitsSQLOwnedColumns(call) {
				violations = append(violations,
					pkg.Fset.Position(call.Pos()).String()+": ."+sel.Sel.Name+
						"(secretNode) does not Omit(secretNodeSQLOwnedColumns...) — it would re-send "+
						"read_count from an in-memory struct and refund reads against MaxReads (#2843)")
			}
			return true
		})
	}

	// Vacuity check: a guard that found nothing to inspect proves nothing. This
	// is exactly the failure mode CLAUDE.md calls out — if a refactor moved both
	// writers out of this package, or the type match silently stopped resolving,
	// the loop above would report zero violations and look green.
	require.GreaterOrEqual(t, checked, 2,
		"expected at least the two known full-struct SecretNode writers (UpdateSecret, TransitionSecretStatus); "+
			"finding fewer means this guard is no longer looking at anything")

	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
}

// TestSecretNodeSQLOwnedColumns_AreRealColumnsOwnedByAConditionalWriter ties the
// list to the schema and to the reason it exists: each entry must be a real
// secret_nodes column (a typo would silently omit nothing, since gorm ignores
// an unknown Omit name).
func TestSecretNodeSQLOwnedColumns_AreRealColumnsOwnedByAConditionalWriter(t *testing.T) {
	ls := newReadCountTestStorage(t)
	require.NotEmpty(t, secretNodeSQLOwnedColumns)
	for _, col := range secretNodeSQLOwnedColumns {
		require.True(t, secretNodeColumnExistsForTest(t, ls, col),
			"secretNodeSQLOwnedColumns names %q, which is not a secret_nodes column — "+
				"gorm silently ignores an unknown Omit name, so the omission would be a no-op", col)
	}
}

// TestUpdateSecret_DoesNotRefundReadsAgainstMaxReads is the behavioural half:
// the exact interleaving from secretNodeSQLOwnedColumns' doc comment. Red before
// the Omit (read_count 1, cap re-opened), green after.
func TestUpdateSecret_DoesNotRefundReadsAgainstMaxReads(t *testing.T) {
	ctx := context.Background()
	ls := newReadCountTestStorage(t)
	secret := seedReadCountSecret(t, ls, 2)

	// An editor loads the secret while the counter is still 0.
	loaded, err := ls.GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	require.Equal(t, 0, loaded.ReadCount)

	// Two readers burn the whole budget.
	for i := range 2 {
		ok, err := ls.TryIncrementSecretNodeReadCount(ctx, secret.ID, 2)
		require.NoError(t, err)
		require.True(t, ok, "read %d should be inside the cap", i+1)
	}
	exhausted, err := ls.TryIncrementSecretNodeReadCount(ctx, secret.ID, 2)
	require.NoError(t, err)
	require.False(t, exhausted, "the cap must be exhausted before the edit")

	// The editor now saves an unrelated metadata change from its stale struct.
	loaded.Description = "an unrelated metadata edit"
	_, err = ls.UpdateSecret(ctx, loaded)
	require.NoError(t, err)

	// The cap must still be exhausted. Before the fix this granted a third read:
	// Save() re-sent read_count = 0.
	refunded, err := ls.TryIncrementSecretNodeReadCount(ctx, secret.ID, 2)
	require.NoError(t, err)
	require.False(t, refunded,
		"an unrelated UpdateSecret refunded a read against MaxReads (#2843): the full-struct "+
			"Save() re-sent the editor's stale read_count")

	// And the edit itself must have landed — the Omit must not have widened into
	// "this write does nothing".
	after, err := ls.GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	require.Equal(t, "an unrelated metadata edit", after.Description)
	require.Equal(t, 2, after.ReadCount, "the database's counter must stand")

	// The returned struct must agree with the database about the counter, so a
	// caller that saves it again does not reintroduce the stale value one layer up.
	require.Equal(t, 2, loaded.ReadCount,
		"UpdateSecret returned a struct whose read_count disagrees with the row it just wrote")
}

// TestTransitionSecretStatus_DoesNotRefundReadsAgainstMaxReads is the same
// invariant for the Select("*") conditional-update path, which had the identical
// defect for the identical reason.
func TestTransitionSecretStatus_DoesNotRefundReadsAgainstMaxReads(t *testing.T) {
	ctx := context.Background()
	ls := newReadCountTestStorage(t)
	secret := seedReadCountSecret(t, ls, 1)

	loaded, err := ls.GetSecret(ctx, secret.ID)
	require.NoError(t, err)

	ok, err := ls.TryIncrementSecretNodeReadCount(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.True(t, ok)

	loaded.Status = "suspended"
	applied, err := ls.TransitionSecretStatus(ctx, loaded, "active")
	require.NoError(t, err)
	require.True(t, applied, "the transition must apply, or this test proves nothing")

	refunded, err := ls.TryIncrementSecretNodeReadCount(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.False(t, refunded,
		"a status transition refunded a read against MaxReads (#2843): Select(\"*\") re-sent "+
			"the caller's stale read_count")

	after, err := ls.GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", after.Status, "the transition's own field must still be persisted")
	require.Equal(t, 1, after.ReadCount)
}

// newReadCountTestStorage builds the minimum real schema these tests need:
// GetSecret/UpdateSecret/TransitionSecretStatus/TryIncrementSecretNodeReadCount
// all touch secret_nodes and nothing else (GetSecret is a plain First on the
// table — see local_secrets.go), so a single-table schema exercises the real
// statements rather than a stand-in.
func newReadCountTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	return NewLocalStorage(db)
}

func seedReadCountSecret(t *testing.T, ls *LocalStorage, maxReads int) *models.SecretNode {
	t.Helper()
	s := &models.SecretNode{
		Name: "burn-after-reads", ProjectID: 1, EnvironmentID: 1,
		IsSecret: true, Status: "active",
		MaxReads: &maxReads, ReadCount: 0,
	}
	require.NoError(t, ls.db.Create(s).Error)
	return s
}

func secretNodeColumnExistsForTest(t *testing.T, ls *LocalStorage, column string) bool {
	t.Helper()
	var count int64
	require.NoError(t, ls.db.Raw(
		"SELECT COUNT(*) FROM pragma_table_info('secret_nodes') WHERE name = ?", column).
		Scan(&count).Error)
	return count > 0
}
