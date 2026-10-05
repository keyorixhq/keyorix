// read_path_cache_guard_test.go — the structural guard that makes GUARD-6's
// bug class unreachable rather than merely fixed: nothing outside
// read_path_cache.go may write a read-path cache ENTRY (a stamp-and-value
// pair). Same style as the existing structural guards
// (internal/core/atomicity_guard_test.go, check_then_act_lock_guard_test.go,
// internal/storage/store/g81_guard_test.go): parse the package's AST, DERIVE
// the thing being checked from the code, fail on a violation.
//
// # Why only entry WRITES
//
// The bug class is "a value cached under a stamp that does not correspond to
// it". Only a write of (stamp, value) can create that. Dropping an entry
// (genCache.drop, invalidateCachedRead) can at worst cost a future cache
// miss, never serve a stale value, so eviction is deliberately NOT restricted
// — stated here so the narrower scope reads as considered rather than
// overlooked. Reads (get/size) are likewise unrestricted.
//
// # What this guard recognises, and what it does not
//
// Recognised:
//   - A cache TYPE: a type declared in package store whose name ends in
//     "cache" (case-insensitive) AND whose struct has at least one field that
//     is a map type or a *genCache[...] instantiation. Derived, not listed, so
//     a future cache type is covered the moment it follows the convention —
//     and rule 2 below closes the "just don't follow the convention" escape.
//   - An ENTRY-WRITING method: a method on such a type whose body assigns to a
//     map element of a receiver field (`c.entries[k] = …`). Derived from the
//     AST, so a method called set/merge/store/put/upsert/anything is covered
//     without naming any of them.
//   - A VIOLATION: a call to any such method, or a direct map-element
//     assignment to a field of a cache-typed selector, from any file other
//     than read_path_cache.go — `_test.go` files included.
//
// NOT recognised, and therefore explicitly not claimed:
//   - A cache built on a bare map field of LocalStorage with no wrapper type
//     at all. Rule 2's mutex+map check catches the common shape of that
//     (a mutex-guarded map always needs a holder), but an unsynchronised bare
//     map would slip through — it would also be a data race, which `go test
//     -race` is the check for.
//   - Any cache outside package store.
//   - A write through reflection, unsafe, or a function value.
//   - Method calls resolved by TYPE rather than by name: this is an AST scan
//     with no type information, so a method named like an entry writer on an
//     unrelated type would be a false positive. Verified at the time of
//     writing that no other type in this package declares a method with any of
//     the derived names (`store` is the only one), and
//     TestReadPathCacheGuard_RealRepo's vacuity assertions fail if the derived
//     set ever becomes empty.
package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// readPathCacheHelperFile is the ONE file allowed to write a cache entry.
const readPathCacheHelperFile = "read_path_cache.go"

// mutexMapTypeExemptions lists types in this package that pair a mutex with a
// map but are NOT read-path caches, with the reason. Without rule 2, renaming a
// cache type would be enough to escape rule 1 — and a guard you can escape by
// renaming is not a guard. Keep this list short and reasoned; a new entry is a
// claim a reviewer can check.
var mutexMapTypeExemptions = map[string]string{
	"namedLockRegistry": "a lock registry (map[string]*namedLockEntry), not a read cache: it hands out mutexes, it never stores a value under a generation stamp",
}

type cacheGuardFindings struct {
	cacheTypes   []string
	entryWriters []string
	violations   []string
	helperWrites int
}

// checkReadPathCacheGuard runs the whole derivation over fsys (a flat
// directory of .go files), so the fixtures below can exercise every rejection
// path without touching the real tree.
func checkReadPathCacheGuard(fsys fs.FS) (cacheGuardFindings, error) {
	var out cacheGuardFindings
	fset := token.NewFileSet()

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return out, err
	}
	files := map[string]*ast.File{}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, rerr := fs.ReadFile(fsys, e.Name())
		if rerr != nil {
			return out, rerr
		}
		f, perr := parser.ParseFile(fset, e.Name(), src, parser.ParseComments)
		if perr != nil {
			return out, fmt.Errorf("%s: %w", e.Name(), perr)
		}
		files[e.Name()] = f
		names = append(names, e.Name())
	}
	sort.Strings(names)

	// Rule 1a — derive the cache types.
	cacheTypes := map[string]bool{}
	mutexMapTypes := map[string]bool{}
	for _, name := range names {
		ast.Inspect(files[name], func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			hasMap, hasGenCache, hasMutex := false, false, false
			for _, field := range st.Fields.List {
				switch {
				case isMapType(field.Type):
					hasMap = true
				case isGenCachePointer(field.Type):
					hasGenCache = true
				case isMutexType(field.Type):
					hasMutex = true
				}
			}
			named := strings.HasSuffix(strings.ToLower(ts.Name.Name), "cache")
			if named && (hasMap || hasGenCache) {
				cacheTypes[ts.Name.Name] = true
			}
			if hasMutex && hasMap && !named {
				mutexMapTypes[ts.Name.Name] = true
			}
			return true
		})
	}
	for t := range cacheTypes {
		out.cacheTypes = append(out.cacheTypes, t)
	}
	sort.Strings(out.cacheTypes)

	// Rule 2 — the naming loophole: a mutex+map type that is not named *Cache
	// must be explained here.
	var unexplained []string
	for t := range mutexMapTypes {
		if _, ok := mutexMapTypeExemptions[t]; !ok {
			unexplained = append(unexplained, t)
		}
	}
	sort.Strings(unexplained)
	for _, t := range unexplained {
		out.violations = append(out.violations, fmt.Sprintf(
			"type %s pairs a mutex with a map but is not named *Cache, so rule 1 would not treat it as a read-path cache. "+
				"Rename it to end in Cache (so the guard covers its writes), or add it to mutexMapTypeExemptions with the reason it is not a read cache.", t))
	}

	// Rule 1b — derive the entry-writing methods: a method on a cache type
	// whose body assigns to a map element of a receiver field.
	writers := map[string]bool{}
	for _, name := range names {
		for _, decl := range files[name].Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
				continue
			}
			recvType := cacheGuardReceiverTypeName(fn.Recv.List[0].Type)
			if !cacheTypes[recvType] {
				continue
			}
			recvName := ""
			if len(fn.Recv.List[0].Names) == 1 {
				recvName = fn.Recv.List[0].Names[0].Name
			}
			if bodyAssignsMapElementOf(fn.Body, recvName) {
				writers[fn.Name.Name] = true
			}
		}
	}
	for w := range writers {
		out.entryWriters = append(out.entryWriters, w)
	}
	sort.Strings(out.entryWriters)

	// Rule 3 — violations: a call to an entry writer, or a direct map-element
	// assignment through a selector, outside the helper file.
	for _, name := range names {
		isHelper := name == readPathCacheHelperFile
		ast.Inspect(files[name], func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || !writers[sel.Sel.Name] {
					return true
				}
				if isHelper {
					out.helperWrites++
					return true
				}
				out.violations = append(out.violations, fmt.Sprintf(
					"%s:%d: calls %s(), a read-path cache entry writer. Only %s may write a cache entry — route this through cachedRead/cachedReadSameRow instead. "+
						"(A stamp-and-value pair written anywhere else is GUARD-6's bug class: see read_path_cache.go's header.)",
					name, fset.Position(node.Pos()).Line, sel.Sel.Name, readPathCacheHelperFile))
			case *ast.AssignStmt:
				if isHelper {
					return true
				}
				for _, lhs := range node.Lhs {
					idx, ok := lhs.(*ast.IndexExpr)
					if !ok {
						continue
					}
					if _, ok := idx.X.(*ast.SelectorExpr); !ok {
						continue
					}
					if !selectorMentionsCacheField(idx.X.(*ast.SelectorExpr)) {
						continue
					}
					out.violations = append(out.violations, fmt.Sprintf(
						"%s:%d: assigns a cache map element directly. Only %s may write a cache entry.",
						name, fset.Position(lhs.Pos()).Line, readPathCacheHelperFile))
				}
			}
			return true
		})
	}
	sort.Strings(out.violations)
	return out, nil
}

func isMapType(e ast.Expr) bool { _, ok := e.(*ast.MapType); return ok }

func isMutexType(e ast.Expr) bool {
	// sync.Mutex / sync.RWMutex, by value or by pointer.
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "sync" && (sel.Sel.Name == "Mutex" || sel.Sel.Name == "RWMutex")
}

// isGenCachePointer matches *genCache[...] with any number of type arguments.
func isGenCachePointer(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch idx := star.X.(type) {
	case *ast.IndexExpr:
		id, ok := idx.X.(*ast.Ident)
		return ok && id.Name == "genCache"
	case *ast.IndexListExpr:
		id, ok := idx.X.(*ast.Ident)
		return ok && id.Name == "genCache"
	}
	return false
}

// cacheGuardReceiverTypeName returns "genCache" for *genCache[K, G, V] and
// "secretMetadataCache" for *secretMetadataCache.
func cacheGuardReceiverTypeName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.IndexListExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

// bodyAssignsMapElementOf reports whether body contains `recv.<field>[…] = …`.
func bodyAssignsMapElementOf(body *ast.BlockStmt, recvName string) bool {
	if recvName == "" {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			idx, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			sel, ok := idx.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if base, ok := sel.X.(*ast.Ident); ok && base.Name == recvName {
				found = true
			}
		}
		return true
	})
	return found
}

// selectorMentionsCacheField is the heuristic half of rule 3: a map-element
// assignment through a selector whose own base selector names something
// cache-ish (`ls.secretMetaCache.nodes[…] = …`). Deliberately narrow and
// named as a heuristic, because without type information a selector chain is
// all there is to go on.
func selectorMentionsCacheField(sel *ast.SelectorExpr) bool {
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(inner.Sel.Name), "cache")
}

// TestReadPathCacheGuard_RealRepo is the guard proper, over the real package.
func TestReadPathCacheGuard_RealRepo(t *testing.T) {
	t.Parallel()
	got, err := checkReadPathCacheGuard(os.DirFS("."))
	require.NoError(t, err)

	require.Empty(t, got.violations,
		"read-path cache guard:\n%s", strings.Join(got.violations, "\n"))

	// Vacuity: a scanner that derives nothing passes for free. These assert the
	// derivation still matches this package's idiom, so a refactor that makes
	// the guard blind fails HERE rather than silently stopping work.
	require.NotEmpty(t, got.cacheTypes, "derived no cache types: the guard has stopped recognising this package's cache idiom")
	require.Contains(t, got.cacheTypes, "genCache")
	require.Contains(t, got.cacheTypes, "secretMetadataCache")
	require.Contains(t, got.cacheTypes, "rolePermissionCache")
	require.NotEmpty(t, got.entryWriters, "derived no entry-writing methods")
	require.Contains(t, got.entryWriters, "store")
	require.Positive(t, got.helperWrites,
		"the helper file itself makes no entry write the guard can see — the call-shape matcher has stopped matching")
}

// ── calibration: every rejection path, both directions, every CI run ────────

const guardCleanHelper = `package store

type genCache[K comparable, V any] struct {
	entries map[K]V
}

func (c *genCache[K, V]) store(k K, v V) { c.entries[k] = v }
func (c *genCache[K, V]) get(k K) (V, bool) { v, ok := c.entries[k]; return v, ok }

func cachedRead[K comparable, V any](c *genCache[K, V], k K, load func() V) V {
	if v, ok := c.get(k); ok {
		return v
	}
	v := load()
	c.store(k, v)
	return v
}
`

func TestReadPathCacheGuard_Fixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		files     fstest.MapFS
		wantMatch string // substring the single expected violation must contain; "" = expect none
	}{
		{
			name: "clean package",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"local_secrets.go": &fstest.MapFile{Data: []byte(`package store

type thing struct{}

func read(c *genCache[uint, *thing]) *thing {
	v, _ := c.get(1)
	return v
}
`)},
			},
		},
		{
			name: "direct entry write outside the helper",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"local_secrets.go": &fstest.MapFile{Data: []byte(`package store

type thing struct{}

func read(c *genCache[uint, *thing]) *thing {
	v := &thing{}
	c.store(1, v)
	return v
}
`)},
			},
			wantMatch: "calls store(), a read-path cache entry writer",
		},
		{
			name: "entry write from a _test.go file is a violation too",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"sneaky_test.go": &fstest.MapFile{Data: []byte(`package store

func plant(c *genCache[uint, int]) { c.store(1, 2) }
`)},
			},
			wantMatch: "sneaky_test.go",
		},
		{
			name: "a renamed cache type is still a cache, and its writer is still restricted",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"other_cache.go": &fstest.MapFile{Data: []byte(`package store

type secretValueCache struct {
	rows map[uint]string
}

func (c *secretValueCache) put(id uint, v string) { c.rows[id] = v }
`)},
				"user.go": &fstest.MapFile{Data: []byte(`package store

func warm(c *secretValueCache) { c.put(1, "x") }
`)},
			},
			wantMatch: "calls put(), a read-path cache entry writer",
		},
		{
			name: "a mutex+map type not named *Cache must be explained",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"sneaky.go": &fstest.MapFile{Data: []byte(`package store

import "sync"

type valueStash struct {
	mu   sync.Mutex
	rows map[uint]string
}
`)},
			},
			wantMatch: "pairs a mutex with a map but is not named *Cache",
		},
		{
			name: "an exempted mutex+map type passes",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"locks.go": &fstest.MapFile{Data: []byte(`package store

import "sync"

type namedLockRegistry struct {
	mu    sync.Mutex
	locks map[string]int
}
`)},
			},
		},
		{
			name: "a direct cache map-element assignment outside the helper",
			files: fstest.MapFS{
				readPathCacheHelperFile: &fstest.MapFile{Data: []byte(guardCleanHelper)},
				"local_secrets.go": &fstest.MapFile{Data: []byte(`package store

type holder struct {
	secretMetaCache struct{ nodes map[uint]int }
}

func plant(ls *holder) { ls.secretMetaCache.nodes[1] = 2 }
`)},
			},
			wantMatch: "assigns a cache map element directly",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkReadPathCacheGuard(tc.files)
			require.NoError(t, err)
			if tc.wantMatch == "" {
				require.Empty(t, got.violations, "expected a clean fixture to pass")
				return
			}
			require.NotEmpty(t, got.violations, "expected the guard to go red on this fixture")
			joined := strings.Join(got.violations, "\n")
			require.Contains(t, joined, tc.wantMatch)
		})
	}
}
