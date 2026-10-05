// cache_enabled_guard_test.go — LocalStorage.cacheEnabled is the whole of the
// fix for the rolled-back-transaction defect (coordinator review of
// #2764/#2767), and both of its failure directions are INVISIBLE:
//
//   - silently false on the root store → every read-path cache is off, in
//     production, with no symptom but a latency number nobody is watching.
//     PERF-3's entire win would evaporate silently.
//   - silently true on a derived/transaction-scoped store → the blocker is
//     back: an uncommitted answer gets published into a cache that outlives
//     the transaction.
//
// Neither shows up in a correctness test, so the flag gets its own guard. The
// positive direction matters as much as the negative one here: a flag that is
// never true is as useless as one that is always true.
package store

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestCacheEnabled_OnForTheRootStoreOffForDerivedOnes pins both directions on
// the real constructors.
func TestCacheEnabled_OnForTheRootStoreOffForDerivedOnes(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	root := NewLocalStorage(db)
	require.True(t, root.cacheEnabled,
		"NewLocalStorage must enable caching — this is the ONLY place it is set, so a refactor that drops it turns every read-path cache off in production with no other symptom")

	sentinel := errors.New("done")
	require.ErrorIs(t, root.WithTransaction(context.Background(), func(tx storage.Storage) error {
		inner, ok := tx.(*LocalStorage)
		require.True(t, ok)
		require.False(t, inner.cacheEnabled,
			"a transaction-scoped LocalStorage must NOT have caching enabled: it reads through the transaction handle, so everything it resolves is uncommitted, and the shared cache outlives the transaction")
		return sentinel
	}), sentinel)
}

// TestCacheEnabled_IsNeverSetOnADerivedLocalStorageLiteral is the structural
// half. Every `&LocalStorage{…}` composite literal in this package other than
// NewLocalStorage's own is a derived store (WithTransaction's clone, and the
// ad-hoc `&LocalStorage{db: tx}` literals in local_rbac.go and the tests), and
// each must leave cacheEnabled at its zero value. Setting it in one of them
// would re-open the blocker for that path alone — the kind of one-site opt-in
// that no behavioural test covers because the path looks identical.
//
// Recognised: a composite literal of type LocalStorage (with or without `&`)
// anywhere in this package, including _test.go files. The one allowed to set
// the field is identified by being inside the function named
// cacheEnabledOwner below, not by file, so moving NewLocalStorage to another
// file does not silently widen the exemption.
//
// NOT recognised, and therefore not claimed: a store built by copying a struct
// value (`cp := *ls`), by reflection, or outside package store. The first of
// those would also copy the db handle and is not an idiom this package uses;
// grep confirms no `:= *ls` on a LocalStorage today.
func TestCacheEnabled_IsNeverSetOnADerivedLocalStorageLiteral(t *testing.T) {
	t.Parallel()
	const cacheEnabledOwner = "NewLocalStorage"

	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()

	var violations []string
	owners := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, perr)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inOwner := fn.Name.Name == cacheEnabledOwner
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isLocalStorageLiteral(lit) {
					return true
				}
				if !literalSetsField(lit, "cacheEnabled") {
					return true
				}
				if inOwner {
					owners++
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s:%d: %s builds a LocalStorage literal that sets cacheEnabled. Only %s may; every other LocalStorage in this package is DERIVED from another (a transaction-scoped clone or an ad-hoc tx handle) and must leave the field false, because it reads uncommitted state through a transaction handle while sharing the parent's cache. See cacheEnabled's doc comment.",
					name, fset.Position(lit.Pos()).Line, fn.Name.Name, cacheEnabledOwner))
				return true
			})
		}
	}

	sort.Strings(violations)
	require.Empty(t, violations, "cacheEnabled set on a derived LocalStorage:\n%s", strings.Join(violations, "\n"))
	require.Equal(t, 1, owners,
		"expected exactly one LocalStorage literal to set cacheEnabled (%s's); got %d. Zero means the flag was dropped and caching is off everywhere; more than one means a second construction path claims to own it.",
		cacheEnabledOwner, owners)
}

func isLocalStorageLiteral(lit *ast.CompositeLit) bool {
	id, ok := lit.Type.(*ast.Ident)
	return ok && id.Name == "LocalStorage"
}

func literalSetsField(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
			return true
		}
	}
	return false
}
