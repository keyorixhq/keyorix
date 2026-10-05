package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDynamicSecretWrites_AreColumnScoped pins the #2698 fix structurally, so it
// holds in a DSN-less run too (the two
// TestCTAReview_{ClassifyDynamicSecretConfig,RenewLease}_vs_* Postgres tests are
// the behavioural proof, and they need real Postgres).
//
// Hops checked: ClassifyDynamicSecretConfig -> c.storage.SetDynamicSecretConfigClassification;
// RenewLease -> c.storage.ExtendDynamicSecretLeaseExpiry; both -> their LocalStorage bodies.
func TestDynamicSecretWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../storage/store/local_dynamic.go", "SetDynamicSecretConfigClassification")
	assertColumnScopedStorageWrite(t, "../storage/store/local_dynamic.go", "ExtendDynamicSecretLeaseExpiry")
	assertColumnScopedStorageWrite(t, "../storage/store/local_dynamic.go", "RecordDynamicSecretLeaseRevocation")

	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "ClassifyDynamicSecretConfig", "storage",
		"SetDynamicSecretConfigClassification", "Save", "UpdateDynamicSecretConfig")
	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "RenewLease", "storage",
		"ExtendDynamicSecretLeaseExpiry", "Save", "UpdateDynamicSecretLease")
	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "RevokeLease", "storage",
		"RecordDynamicSecretLeaseRevocation", "Save", "UpdateDynamicSecretLease")
}

// TestUpdateDynamicSecretLease_HasNoProductionCaller is the half that does NOT
// depend on anyone remembering to update a per-function guard.
//
// #2698 could not DELETE the two full-row primitives the way #2696 and #2697
// deleted theirs: `UpdateDynamicSecretConfig` still has one production caller,
// CreateDynamicSecretConfig's encrypted-DSN write, and that call site belongs to
// #2651 — fixed in open PR #2675 with SetDynamicSecretConfigAdminDSN, in the same
// few lines of local_dynamic.go and interface.go. Deleting the method here would
// have made this PR conflict with one the coordinator is about to merge, for no
// safety gain.
//
// So the property is enforced by derivation instead of by removal, which is the
// stronger form anyway: a sweep over every non-test file under internal/core and
// server/ asserting that NOTHING calls the full-row lease writer. UpdateDynamicSecretConfig
// is asserted down to its ONE known remaining caller, named explicitly, so the
// count going UP fails here and #2675 landing lets the allowance drop to zero
// (at which point both methods can simply be deleted).
//
// What this does not cover: a call reached through a helper that itself takes a
// storage.Storage, or reflection. Both are absent from this repo's storage call
// style, and this test's own job is the direct-call shape the defect took.
func TestUpdateDynamicSecretLease_HasNoProductionCaller(t *testing.T) {
	// file -> enclosing func, for the one deliberately-remaining caller.
	allowed := map[string]string{
		"internal/core/dynamic_secrets.go:UpdateDynamicSecretConfig": "CreateDynamicSecretConfig — the encrypted-DSN " +
			"write, which is #2651's site, not #2698's; open PR #2675 moves it to SetDynamicSecretConfigAdminDSN. " +
			"Drop this entry (and delete both full-row methods) once that lands.",
	}

	root := dynGuardRepoRoot(t)
	found := map[string][]string{} // key -> enclosing funcs
	for _, dir := range []string{"internal/core", "internal/storage/store", "server"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			require.NoError(t, rerr)
			// The implementations themselves are the definitions, not callers.
			if rel == filepath.Join("internal", "storage", "store", "local_dynamic.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Logf("skipping unparseable %s: %v", rel, perr)
				return nil
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := ce.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "UpdateDynamicSecretLease", "UpdateDynamicSecretConfig":
						key := rel + ":" + sel.Sel.Name
						found[key] = append(found[key], fd.Name.Name)
					}
					return true
				})
			}
			return nil
		})
		require.NoError(t, err)
	}

	for key, funcs := range found {
		if _, ok := allowed[key]; ok {
			continue
		}
		t.Errorf("%s is still called from production code (%v) — #2698 moved every write of these two "+
			"models onto column-scoped conditional methods; a full-row Save here reverts whatever a "+
			"narrower concurrent writer changed (the dynamic-secret kill switch, a lease revocation)",
			key, funcs)
	}
	for key, why := range allowed {
		if _, ok := found[key]; !ok {
			t.Errorf("allowed entry %q no longer matches any call site — delete it (and, if both full-row "+
				"methods are now callerless, delete the methods). Reason it was allowed: %s", key, why)
		}
	}
}

// dynGuardRepoRoot walks up from this package to the directory holding go.mod.
func dynGuardRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate the repo root (no go.mod found walking up from the test's working directory)")
	return ""
}
