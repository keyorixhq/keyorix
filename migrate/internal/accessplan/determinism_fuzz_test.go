package accessplan

// determinism_fuzz_test.go: FuzzAccessPlanBuild is the determinism + no-panic target for the
// pure-transformation Build function. Build is network-free — it takes already-read Vault
// policy and role data and returns a Plan — so there is no hostile HTTP server here. The oracle
// that fits is DETERMINISM: the same BuildInput passed to Build twice must produce deeply
// equal Plans. Any non-deterministic map iteration in the resolution chain
// (PathMapper.Resolve, compactUnmappable, roleName) would be detected quickly by the seed corpus.
//
// Oracles (what each does NOT verify):
//   - NO-PANIC: the Go fuzzer catches panics from the production code directly.
//   - DETERMINISM: Build(in, mapper, issuer) called twice must return deeply equal Plans
//     (reflect.DeepEqual: every Item field, slices in emitted order).
//     Does NOT verify the CORRECTNESS of any individual item (whether the proposed permissions
//     are truly a subset of what the Vault policy allowed — that is ADR-114's scope-monotone
//     property, which the existing ScopeWidening and SMT model export tests cover).
//   - Kubernetes and userpass builder paths: not fuzzed (BuildInput.KubernetesRoles and
//     UserpassUsers are always empty here). Those paths share identical policy-resolution logic
//     with the AppRole arm; they are covered by the existing authroles unit tests.
//   - Cross-mount evidence accumulation: requires a Vault KV tree listing (SetKVTree) that
//     varies by input; not fuzzed here.
//   - Reconcile / Apply: downstream of Build; separate code with its own tests.

import (
	"reflect"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// newFuzzBuildMapper creates a minimal PathMapper covering two projects (team-a, team-b) each
// with one environment and one KV v2 mount. Returned fresh per test run; PathMapper is
// read-only after construction.
func newFuzzBuildMapper(t *testing.T) *PathMapper {
	t.Helper()
	projects := []ProjectRef{{ID: 1, Name: "team-a"}, {ID: 2, Name: "team-b"}}
	envs := map[int][]EnvironmentRef{
		1: {{ID: 10, Name: "prod"}},
		2: {{ID: 20, Name: "prod"}},
	}
	mounts := []KVMountInfo{{Path: "secret/", KVVersion: 2}}
	m, err := NewPathMapper(projects, envs, mounts, nil)
	if err != nil {
		t.Fatalf("newFuzzBuildMapper: %v", err)
	}
	m.SetKVTree(map[string]KVMountListing{
		"secret/": {RootListed: true, Projects: map[string]KVProjectListing{
			"team-a": {Listed: true, Envs: []string{"prod"}},
			"team-b": {Listed: true, Envs: []string{"prod"}},
		}},
	})
	return m
}

// fuzzDecodeCaps converts one byte into a Vault capability list for the fuzz decoder.
func fuzzDecodeCaps(b byte) []string {
	all := [][]string{
		{"read"},
		{"create", "update"},
		{"delete"},
		{"read", "create", "update", "delete"},
		{"read", "list"},
		{"sudo"},
		{"deny"},
		{"create"},
	}
	return all[int(b)%len(all)]
}

func FuzzAccessPlanBuild(f *testing.F) {
	// Seeds exercising different PathMapper.Resolve outcomes.
	for _, s := range []struct {
		path1, path2 string
		caps         byte
	}{
		{"secret/data/team-a/prod/*", "", 0},                          // exact project+env match
		{"secret/data/team-a/*", "", 0},                               // project-only (env=0)
		{"*", "", 5},                                                  // sudo → Unmappable/sudo
		{"secret/data/no-such-team/prod/*", "", 0},                    // unknown project → Unmappable
		{"secret/data/team-a/prod/*", "", 2},                          // delete capability
		{"secret/data/team-a/prod/*", "secret/data/team-b/prod/*", 3}, // two mappable policies
		{"secret/metadata/team-a/prod/*", "", 0},                      // metadata path → Unmappable/metadata-only
		{"secret/data/team-a/prod/db-password", "", 0},                // exact path → Unmappable/narrower
		{"{{identity.entity.id}}/secret/*", "", 0},                    // templated path
		{"", "", 0}, // empty path
	} {
		f.Add(s.path1, s.path2, s.caps)
	}

	f.Fuzz(func(t *testing.T, path1, path2 string, capsB byte) {
		if path1 == "" && path2 == "" {
			return // nothing to build; trivially passes
		}

		mapper := newFuzzBuildMapper(t)

		var blocks []healthscan.PolicyPathBlock
		if path1 != "" {
			blocks = append(blocks, healthscan.PolicyPathBlock{Path: path1, Capabilities: fuzzDecodeCaps(capsB)})
		}
		if path2 != "" {
			blocks = append(blocks, healthscan.PolicyPathBlock{Path: path2, Capabilities: fuzzDecodeCaps(capsB + 1)})
		}

		pol := healthscan.Policy{Name: "fuzz-pol", Blocks: blocks}
		role := healthscan.AppRoleRoleConfig{
			Mount:         "auth/approle",
			Name:          "fuzz-role",
			TokenPolicies: []string{"fuzz-pol"},
		}
		in := BuildInput{
			Policies: []healthscan.Policy{pol},
			AppRoles: []healthscan.AppRoleRoleConfig{role},
		}

		p1 := Build(in, mapper, "")
		p2 := Build(in, mapper, "")

		// DETERMINISM: both calls with identical input must produce identical output.
		if !reflect.DeepEqual(p1, p2) {
			t.Fatalf("DETERMINISM: Build(path1=%q path2=%q caps=%d) produced different plans:\np1 items: %+v\np2 items: %+v",
				path1, path2, capsB, p1.Items, p2.Items)
		}
	})
}
