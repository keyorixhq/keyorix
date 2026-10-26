package core

// hook_storage_selftest_test.go — CORE-MOCKS-SLIM-1.
//
// Pins the behaviour hookStore promises (hook_storage_test.go) and keeps the
// [internal/core.test] archive from growing back: a second type embedding the whole
// storage.Storage interface costs ~2.6 MB of wrapper code each, which is how 123 of
// them made the archive 326-434 MB.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

var _ storage.Storage = (*hookStore)(nil)

func TestHookStore_UnhookedMethodDelegatesToTheInnerStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	hookedCalls := 0
	inner := hooked(nil, &storeHooks{
		GetUser: func(storage.Storage, context.Context, uint) (*models.User, error) {
			return &models.User{ID: 42}, nil
		},
	})
	outer := hooked(inner, &storeHooks{
		GetRole: func(storage.Storage, context.Context, uint) (*models.Role, error) {
			hookedCalls++
			return nil, errors.New("hooked")
		},
	})

	_, err := outer.GetRole(ctx, 1)
	require.EqualError(t, err, "hooked")
	assert.Equal(t, 1, hookedCalls, "a hooked method runs its hook")

	u, err := outer.GetUser(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, uint(42), u.ID, "an un-hooked method must reach the inner store, as a promoted method did")
}

func TestHookStore_UnhookedMethodOnANilInnerStoreFailsLoudly(t *testing.T) {
	t.Parallel()
	spy := hooked(nil, &storeHooks{
		GetRole: func(storage.Storage, context.Context, uint) (*models.Role, error) { return nil, nil },
	})
	assert.Panics(t, func() { _, _ = spy.GetUser(context.Background(), 1) },
		"a pure spy must never silently answer a method nobody faked")
}

func TestHookStore_WithTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage) // WithTransaction hands fn the store itself

	var rawTx storage.Storage
	raw := hooked(ms, &storeHooks{})
	require.NoError(t, raw.WithTransaction(ctx, func(tx storage.Storage) error { rawTx = tx; return nil }))
	assert.Same(t, ms, rawTx, "without WrapTx the callback gets the inner store's own handle: a hook does not fire inside the transaction")

	fired := 0
	wrapped := hooked(ms, &storeHooks{
		WrapTx: true,
		GetRole: func(storage.Storage, context.Context, uint) (*models.Role, error) {
			fired++
			return nil, errors.New("injected")
		},
	})
	require.NoError(t, wrapped.WithTransaction(ctx, func(tx storage.Storage) error {
		_, err := tx.GetRole(ctx, 1)
		assert.EqualError(t, err, "injected", "with WrapTx the hook also fires on the transaction handle")
		return nil
	}))
	assert.Equal(t, 1, fired)

	var overridden bool
	custom := hooked(ms, &storeHooks{WithTransaction: func(storage.Storage, context.Context, func(storage.Storage) error) error {
		overridden = true
		return nil
	}})
	require.NoError(t, custom.WithTransaction(ctx, func(storage.Storage) error { return errors.New("must not run") }))
	assert.True(t, overridden)
}

// The combined reads are served by the store in one statement that never calls the
// per-statement reads a test overrides; hookStore must compose them over itself when a
// feeding read is hooked (the PERF-FIX-6/7 rule), and otherwise delegate untouched.
func TestHookStore_CombinedReadsMeetTheHooksThatFeedThem(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	innerAnswered := map[string]bool{}
	inner := hooked(nil, &storeHooks{
		GetSessionAuthLiveness: func(storage.Storage, context.Context, uint, uint) (*storage.SessionAuthLiveness, error) {
			innerAnswered["session"] = true
			return &storage.SessionAuthLiveness{}, nil
		},
		ResolveUserPermissionAt: func(storage.Storage, context.Context, uint, storage.Scope, string) (*storage.PrincipalPermission, error) {
			innerAnswered["user"] = true
			return &storage.PrincipalPermission{}, nil
		},
		ResolveMachinePermissionAt: func(storage.Storage, context.Context, uint, storage.Scope, string) (*storage.PrincipalPermission, error) {
			innerAnswered["machine"] = true
			return &storage.PrincipalPermission{}, nil
		},
	})

	// Nothing hooked: delegate to the inner store's own combined read.
	plain := hooked(inner, &storeHooks{})
	_, _ = plain.GetSessionAuthLiveness(ctx, 1, 1)
	_, _ = plain.ResolveUserPermissionAt(ctx, 1, storage.Scope{}, "p")
	_, _ = plain.ResolveMachinePermissionAt(ctx, 1, storage.Scope{}, "p")
	assert.Equal(t, map[string]bool{"session": true, "user": true, "machine": true}, innerAnswered)

	// A feeding read hooked: the combined read is composed over the hookStore, so the
	// hook is met and the inner combined read is NOT used.
	innerAnswered = map[string]bool{}
	boom := errors.New("injected read fault")
	faulted := hooked(inner, &storeHooks{
		GetUserRoleIDsAt: func(storage.Storage, context.Context, uint, storage.Scope) ([]uint, error) { return nil, boom },
		GetMachineRoleIDsAt: func(storage.Storage, context.Context, uint, storage.Scope) ([]uint, error) {
			return nil, boom
		},
		GetUser: func(storage.Storage, context.Context, uint) (*models.User, error) { return nil, boom },
		GetSessionByID: func(storage.Storage, context.Context, uint) (*models.Session, error) {
			return nil, boom
		},
	})
	_, err := faulted.ResolveUserPermissionAt(ctx, 1, storage.Scope{}, "p")
	assert.ErrorIs(t, err, boom, "a hooked GetUserRoleIDsAt must reach Authorize through ResolveUserPermissionAt")
	_, err = faulted.ResolveMachinePermissionAt(ctx, 1, storage.Scope{}, "p")
	assert.ErrorIs(t, err, boom, "a hooked GetMachineRoleIDsAt must reach AuthorizePrincipal through ResolveMachinePermissionAt")
	live, err := faulted.GetSessionAuthLiveness(ctx, 1, 1)
	require.NoError(t, err)
	require.NotNil(t, live)
	assert.Empty(t, innerAnswered, "the inner combined reads must be bypassed when a feeding read is hooked")

	// A hook on the combined read itself wins over composition.
	direct := hooked(inner, &storeHooks{
		GetUser: func(storage.Storage, context.Context, uint) (*models.User, error) { return nil, boom },
		GetSessionAuthLiveness: func(storage.Storage, context.Context, uint, uint) (*storage.SessionAuthLiveness, error) {
			return nil, errors.New("combined hook")
		},
	})
	_, err = direct.GetSessionAuthLiveness(ctx, 1, 1)
	assert.EqualError(t, err, "combined hook")
}

// ---- guard: no second whole-Storage embedding in the in-package tests ----

// storageEmbedNames are the type names whose embedding drags the whole 1,087-method
// Storage method set into the embedding type's wrapper set.
var storageEmbedNames = map[string]bool{
	"Storage":      true, // storage.Storage / corestorage.Storage / coreStorage.Storage
	"LocalStorage": true, // *store.LocalStorage
	"MockStorage":  true, // testify mock with ~480 methods
	"hookStore":    true,
	"HookStore":    true, // storagetest.HookStore, the kit's one allowed embedding
}

// wholeStorageEmbeddingViolations returns "file: Type embeds X" for every struct type
// declared in a `package core` or `package coretests` file of files (path -> source) that
// anonymously embeds a whole-Storage type, directly or through another such struct in the
// same package. core's hookStore itself is the one allowed embedding.
func wholeStorageEmbeddingViolations(t *testing.T, files map[string][]byte) []string {
	t.Helper()
	type decl struct {
		file, pkg, name string
		embeds          []string
	}
	structs := map[string]decl{} // keyed "<package>.<type>": core and coretests may reuse a name
	fset := token.NewFileSet()
	for path, src := range files {
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		require.NoError(t, err, path)
		if f.Name.Name != "core" && f.Name.Name != "coretests" {
			continue // internal/core_test is a separate archive; coretests is core's black-box test package (ADR-121)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				dd := decl{file: path, pkg: f.Name.Name, name: ts.Name.Name}
				for _, field := range st.Fields.List {
					if len(field.Names) != 0 {
						continue
					}
					e := field.Type
					if star, ok := e.(*ast.StarExpr); ok {
						e = star.X
					}
					switch x := e.(type) {
					case *ast.Ident:
						dd.embeds = append(dd.embeds, x.Name)
					case *ast.SelectorExpr:
						dd.embeds = append(dd.embeds, x.Sel.Name)
					}
				}
				structs[dd.pkg+"."+dd.name] = dd
			}
		}
	}
	// A struct is "heavy" if it embeds a storage name or another heavy struct.
	heavy := map[string]string{}
	for changed := true; changed; {
		changed = false
		for key, d := range structs {
			if _, done := heavy[key]; done {
				continue
			}
			for _, e := range d.embeds {
				if storageEmbedNames[e] {
					heavy[key], changed = e, true
					break
				}
				if _, ok := heavy[d.pkg+"."+e]; ok {
					heavy[key], changed = e, true
					break
				}
			}
		}
	}
	var out []string
	for key, via := range heavy {
		if key == "core.hookStore" {
			continue
		}
		out = append(out, structs[key].file+": "+structs[key].name+" embeds "+via)
	}
	sort.Strings(out)
	return out
}

// coreTestFiles reads the _test.go files directly in internal/core (keyed by base
// name) and in each of testOnlyDirs (keyed by repository-relative path), all
// relative to root. The test-only dirs are srcpath.CoreTestOnlyDirs in the real
// guard, so a double that moves to internal/core/coretests stays in the scan
// (ADR-121 R5).
func coreTestFiles(t *testing.T, root string, testOnlyDirs []string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for i, dir := range append([]string{srcpath.CoreDir}, testOnlyDirs...) {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		require.NoError(t, err, dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			key := dir + "/" + e.Name()
			if i == 0 {
				key = e.Name()
			}
			src, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(dir), e.Name())) // #nosec G304 -- directory listing of core's own test files
			require.NoError(t, rerr)
			files[key] = src
		}
	}
	return files
}

func TestNoWholeStorageEmbeddingInCoreTests(t *testing.T) {
	t.Parallel()
	files := coreTestFiles(t, srcpath.RepoRoot(), srcpath.CoreTestOnlyDirs)
	// hookStore itself moved to the storagetest kit (CORE-TESTKIT-1): pin that the one
	// allowed whole-Storage embedding still exists there, and that core reaches it
	// only through the alias file.
	kit, kerr := os.ReadFile("storage/storagetest/hookstore.go") // #nosec G304 -- fixed path inside this repo
	require.NoError(t, kerr)
	require.Contains(t, string(kit), "type HookStore struct", "the kit must still hold the one allowed whole-Storage embedding")
	require.Contains(t, files, "storagetest_aliases_test.go", "the scan must cover the alias file that exposes hookStore to core's tests")
	require.Contains(t, files, "internal/core/coretests/main_test.go", "the scan must cover the black-box test package internal/core/coretests")
	assert.Empty(t, wholeStorageEmbeddingViolations(t, files),
		"a test double must not embed the whole storage.Storage (or *store.LocalStorage, MockStorage, hookStore): "+
			"each embedding costs ~2.6 MB of wrapper code in the [internal/core.test] archive. "+
			"Build it with hooked(inner, &storeHooks{...}) instead (storage/storagetest/hookstore.go)")
}

// Calibration: the guard flags a direct embedding in each of its spellings and a
// chained one, ignores hookStore itself, other packages and non-embedding fields.
func TestNoWholeStorageEmbeddingInCoreTests_Calibration(t *testing.T) {
	t.Parallel()
	bad := []byte(`package core
type a struct{ storage.Storage }
type b struct {
	*store.LocalStorage
	n int
}
type c struct{ *MockStorage }
type d struct{ *hookStore }
type e struct{ a }
type f struct{ *storagetest.HookStore }
type hookStore struct{ storage.Storage }
type fine struct{ inner storage.Storage }
type alsoFine struct{ *captureStore }
type aliased = storagetest.HookStore
`)
	assert.Equal(t, []string{
		"x_test.go: a embeds Storage",
		"x_test.go: b embeds LocalStorage",
		"x_test.go: c embeds MockStorage",
		"x_test.go: d embeds hookStore",
		"x_test.go: e embeds a",
		"x_test.go: f embeds HookStore",
	}, wholeStorageEmbeddingViolations(t, map[string][]byte{"x_test.go": bad}))
	assert.Empty(t, wholeStorageEmbeddingViolations(t, map[string][]byte{"y_test.go": []byte("package core_test\ntype z struct{ storage.Storage }\n")}),
		"the external test package has its own archive")
}

// Calibration for the test-only dirs (ADR-121 R5): a whole-storage embedding in
// a package coretests file under internal/core/coretests is found through the
// same file listing the real guard uses, next to one in internal/core itself;
// non-test files and the kit's own HookStore are not scanned.
func TestNoWholeStorageEmbeddingInCoreTests_CalibrationTestOnlyDirs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for rel, body := range map[string]string{
		"internal/core/a_test.go":           "package core\ntype a struct{ storage.Storage }\ntype dup struct{ n int }\n",
		"internal/core/coretests/b_test.go": "package coretests\ntype b struct{ *storagetest.MockStorage }\n",
		"internal/core/coretests/c_test.go": "package coretests\ntype c struct{ *storagetest.HookStore }\ntype fine struct{ inner storage.Storage }\n" +
			"type dup struct{ storage.Storage }\ntype hookStore struct{ storage.Storage }\ntype g struct{ c }\n",
		"internal/core/coretests/helper.go":              "package coretests\ntype notATest struct{ storage.Storage }\n",
		"internal/core/storage/storagetest/hookstore.go": "package storagetest\ntype HookStore struct{ storage.Storage }\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	files := coreTestFiles(t, root, []string{"internal/core/coretests", "internal/core/storage/storagetest"})
	assert.Equal(t, []string{
		"a_test.go: a embeds Storage",
		"internal/core/coretests/b_test.go: b embeds MockStorage",
		"internal/core/coretests/c_test.go: c embeds HookStore",
		"internal/core/coretests/c_test.go: dup embeds Storage",
		"internal/core/coretests/c_test.go: g embeds c",
		"internal/core/coretests/c_test.go: hookStore embeds Storage",
	}, wholeStorageEmbeddingViolations(t, files),
		"only core's own hookStore is exempt, and a name reused across the two packages must not hide either type")
}
