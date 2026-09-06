// rotation_executor_registry_exhaustiveness_test.go — a structural guard, in the same
// family as account_state_exhaustiveness_guard_test.go, statically proving that every
// rotation-backend executor constructor declared in internal/rotation is known to and
// covered by this package's orchestrator-level rotation lock (rotationBackendLock /
// applyBackendRotation, see rotation_orchestrator_lock_test.go).
//
// The lock itself is keyed purely by (backend, ref) and never inspects the concrete
// rotation.Executor type (TestRotationBackendLock_KeyedByBackendAndRefOnly proves
// this), so in principle every executor is ALREADY covered structurally, by
// construction, the moment it's registered through a *rotation.Manager. What this file
// guards against is a hand-maintained list quietly going stale: if a future 4th (5th,
// ...) backend constructor is added to internal/rotation and nobody re-derives that
// this claim still holds for it, that omission must fail loudly here -- not pass
// silently because nobody thought to update a list. This mirrors the campaign's
// established pattern (enumerate by call shape via source, not by a maintained list --
// see server/http/raw_storage_bypass_guard_test.go and
// internal/core/csv_writer_completeness_test.go for the same idiom applied elsewhere).
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/rotation"
)

// knownRotationExecutorConstructors is every internal/rotation constructor this file
// has verified is instantiable and registers correctly through a *rotation.Manager
// (TestRotationExecutorRegistry_AllKnownConstructorsRegisterAndResolve). Each entry's
// factory builds a minimal, harmless instance (a bogus DSN/region, one allowed_refs
// entry) purely to prove construction + registration + Manager.Get resolution work
// identically regardless of type -- it deliberately never calls Rotate/
// GenerateUpstream on these real instances (that would attempt a real network/DB call).
// The actual concurrency proof uses a generic fake executor instead (see
// rotation_orchestrator_lock_test.go) precisely because the lock does not care about
// concrete type -- this map exists ONLY to be checked for completeness against the
// real source below, not to re-prove the locking mechanism per backend.
var knownRotationExecutorConstructors = map[string]func(name string) rotation.Executor{
	"NewAWSIAMExecutor": func(name string) rotation.Executor {
		return rotation.NewAWSIAMExecutor(name, "us-east-1", []string{"svc-"})
	},
	"NewAzureAppSecretExecutor": func(name string) rotation.Executor {
		return rotation.NewAzureAppSecretExecutor(name, []string{"svc-"})
	},
	"NewGCPServiceAccountKeyExecutor": func(name string) rotation.Executor {
		return rotation.NewGCPServiceAccountKeyExecutor(name, []string{"svc-"})
	},
	"NewPostgresExecutor": func(name string) rotation.Executor {
		return rotation.NewPostgresExecutor(name, "postgres://unused/unused", []string{"svc-"})
	},
	"NewMySQLExecutor": func(name string) rotation.Executor {
		return rotation.NewMySQLExecutor(name, "unused:unused@tcp(unused)/unused", []string{"svc-"})
	},
	"NewMongoExecutor": func(name string) rotation.Executor {
		return rotation.NewMongoExecutor(name, "mongodb://unused/unused", []string{"svc-"})
	},
	"NewRedisExecutor": func(name string) rotation.Executor {
		return rotation.NewRedisExecutor(name, "redis://unused/0", []string{"svc-"})
	},
}

// TestRotationExecutorRegistry_NoUncoveredConstructor parses internal/rotation's
// actual source (not a filename list) and fails if it declares an exported
// `New*Executor` top-level constructor that knownRotationExecutorConstructors above
// does not know about -- the guard against a silently-missed future backend.
func TestRotationExecutorRegistry_NoUncoveredConstructor(t *testing.T) {
	discovered := discoverRotationExecutorConstructors(t)
	if len(discovered) == 0 {
		t.Fatal("found zero New*Executor constructors in internal/rotation -- the discovery logic itself is broken")
	}

	var uncovered []string
	for _, name := range discovered {
		if _, ok := knownRotationExecutorConstructors[name]; !ok {
			uncovered = append(uncovered, name)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Errorf("internal/rotation declares constructor(s) %v not present in knownRotationExecutorConstructors "+
			"(rotation_executor_registry_exhaustiveness_test.go) -- add each one there (and re-run "+
			"TestRotationExecutorRegistry_AllKnownConstructorsRegisterAndResolve) before landing; a new rotation "+
			"backend must never silently ship without confirming it goes through applyBackendRotation's central "+
			"(backend, ref) lock like every other backend", uncovered)
	}
}

// TestRotationExecutorRegistry_AllKnownConstructorsRegisterAndResolve builds every
// known constructor's executor, registers them all in ONE *rotation.Manager (the exact
// registry applyBackendRotation calls Get on), and confirms every one resolves back by
// name -- proving the registry/Get mechanism applyBackendRotation depends on is
// type-agnostic across every currently known backend, not just the three
// generate-upstream ones (AWS/Azure/GCP) this fix's finding named explicitly.
func TestRotationExecutorRegistry_AllKnownConstructorsRegisterAndResolve(t *testing.T) {
	var execs []rotation.Executor
	for name, factory := range knownRotationExecutorConstructors {
		execs = append(execs, factory(name))
	}
	mgr := rotation.NewManager(execs)

	names := mgr.Names()
	if len(names) != len(knownRotationExecutorConstructors) {
		t.Fatalf("expected %d distinct registered backends, got %d (%v) -- a name collision or construction failure silently dropped one",
			len(knownRotationExecutorConstructors), len(names), names)
	}
	for name := range knownRotationExecutorConstructors {
		exec, ok := mgr.Get(name)
		if !ok {
			t.Errorf("Manager.Get(%q) returned not-found after registration", name)
			continue
		}
		if exec.Name() != name {
			t.Errorf("Manager.Get(%q) returned an executor whose own Name() is %q", name, exec.Name())
		}
	}
}

// discoverRotationExecutorConstructors parses every non-test .go file in
// internal/rotation and returns the name of each exported top-level function matching
// `New*Executor` (e.g. NewAWSIAMExecutor) -- the actual, current set of rotation
// backend constructors, derived from source rather than hand-maintained, so this
// enumeration can't silently go stale as backends are added or renamed.
//
// Reads the directory and parses each file individually (rather than go/parser's
// ParseDir, deprecated since Go 1.25) so this stays simple dependency-free source
// inspection, matching account_state_exhaustiveness_guard_test.go's per-file idiom.
func discoverRotationExecutorConstructors(t *testing.T) []string {
	t.Helper()
	const dir = "../rotation"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var names []string
	for _, entry := range entries {
		n := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, dir+"/"+n, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s/%s: %v", dir, n, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil { // skip methods; only top-level funcs are constructors
				continue
			}
			if !fd.Name.IsExported() {
				continue
			}
			name := fd.Name.Name
			if strings.HasPrefix(name, "New") && strings.HasSuffix(name, "Executor") {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}
