package accessplan

import (
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// Cross-mount convention (ask rd-smt-fix-cross-mount-convention, option c): under the default
// convention "secret/data/team-a/prod/x" and "kv1/team-a/prod/x" both belong to team-a/prod, so
// a grant from a policy on one mount would also reach the other mount's imported secrets. The
// default convention maps only when plan-access listed every other KV mount and found nothing
// under the same <project>/ (project grant) or <project>/<env>/ (environment grant).

// kvTree builds a listing where each mount is listed and holds the given "<project>/<env>"
// (or bare "<project>") keys.
func kvTree(mounts map[string][]string) map[string]KVMountListing {
	tree := map[string]KVMountListing{}
	for mount, keys := range mounts {
		l := KVMountListing{RootListed: true, Projects: map[string]KVProjectListing{}}
		for _, k := range keys {
			project, env, _ := strings.Cut(k, "/")
			p := l.Projects[project]
			p.Listed = true
			if env != "" {
				p.Envs = append(p.Envs, env)
			}
			l.Projects[project] = p
		}
		tree[mount] = l
	}
	return tree
}

func crossMountMapper(t *testing.T, tree map[string]KVMountListing) *PathMapper {
	t.Helper()
	m := testMapper(t)
	m.SetKVTree(tree)
	return m
}

func TestCrossMount_OtherMountHoldsSameEnvironment_Unmappable(t *testing.T) {
	m := crossMountMapper(t, kvTree(map[string][]string{"secret/": {"team-a/prod"}, "kv1/": {"team-a/prod"}}))
	res, category, reason, ok := m.Resolve("secret/data/team-a/prod/*")
	if ok || category != CategoryCrossMountScope {
		t.Fatalf("ok=%v category=%q, want Unmappable/%s: kv1/team-a/prod/ lands in the same environment", ok, category, CategoryCrossMountScope)
	}
	if !strings.Contains(reason, "kv1/team-a/prod/") || !strings.Contains(reason, "--path-map") {
		t.Fatalf("reason %q must name the other mount's path and the --path-map way out", reason)
	}
	if !slices.Contains(res.CrossMountEvidence, "kv1/team-a/prod/: present") {
		t.Fatalf("evidence %v must record what kv1 held", res.CrossMountEvidence)
	}
	// The same check from the KV v1 side.
	if _, category, _, ok := m.Resolve("kv1/team-a/prod/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("kv1/team-a/prod/*: ok=%v category=%q, want Unmappable/%s", ok, category, CategoryCrossMountScope)
	}
}

func TestCrossMount_OtherMountHoldsOtherEnvironmentOnly_Maps(t *testing.T) {
	m := crossMountMapper(t, kvTree(map[string][]string{"secret/": {"team-a/prod"}, "kv1/": {"team-a/dev"}}))
	res, category, reason, ok := m.Resolve("secret/data/team-a/prod/*")
	if !ok {
		t.Fatalf("Unmappable %s (%s): kv1 holds only team-a/dev, not team-a/prod", category, reason)
	}
	want := []string{"kv1/team-a/prod/: absent", "secret/team-a/prod/: policy mount"}
	if !slices.Equal(res.CrossMountEvidence, want) {
		t.Fatalf("evidence = %v, want %v", res.CrossMountEvidence, want)
	}
	// A project-wide grant covers team-a/dev too, which kv1 holds.
	if _, category, _, ok := m.Resolve("secret/data/team-a/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("secret/data/team-a/*: ok=%v category=%q, want Unmappable/%s (kv1 has team-a/)", ok, category, CategoryCrossMountScope)
	}
}

func TestCrossMount_SecretAtEnvironmentLevelCounts(t *testing.T) {
	// "kv1/team-a/prod" stored as a secret (not a directory): fail closed, it is a path there.
	m := crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-a/prod"}}))
	if _, category, _, ok := m.Resolve("secret/data/team-a/prod/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("ok=%v category=%q, want Unmappable/%s", ok, category, CategoryCrossMountScope)
	}
}

func TestCrossMount_UnlistedMountOrProject_FailsClosed(t *testing.T) {
	tree := kvTree(map[string][]string{"secret/": {"team-a/prod"}})
	tree["kv1/"] = KVMountListing{RootListed: false}
	m := crossMountMapper(t, tree)
	if _, category, reason, ok := m.Resolve("secret/data/team-a/prod/*"); ok || category != CategoryCrossMountScope || !strings.Contains(reason, "not listed") {
		t.Fatalf("root not listable: ok=%v category=%q reason=%q, want Unmappable/%s naming the unlisted mount", ok, category, reason, CategoryCrossMountScope)
	}

	tree["kv1/"] = KVMountListing{RootListed: true, Projects: map[string]KVProjectListing{"team-a": {Listed: false}}}
	m = crossMountMapper(t, tree)
	if _, category, _, ok := m.Resolve("secret/data/team-a/prod/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("kv1/team-a/ not listable: ok=%v category=%q, want Unmappable/%s", ok, category, CategoryCrossMountScope)
	}
	// The project key itself was listed, so a project grant already knows kv1 holds team-a/.
	if _, category, _, ok := m.Resolve("secret/data/team-a/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("project grant: ok=%v category=%q, want Unmappable/%s", ok, category, CategoryCrossMountScope)
	}
	// A mount missing from the listing (enabled after the listing) is unlisted too.
	m = crossMountMapper(t, kvTree(map[string][]string{"secret/": nil}))
	if _, category, _, ok := m.Resolve("secret/data/team-a/prod/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("kv1 missing from the listing: ok=%v category=%q, want Unmappable/%s", ok, category, CategoryCrossMountScope)
	}
}

func TestCrossMount_NoListing(t *testing.T) {
	m := crossMountMapper(t, nil)
	if _, category, _, ok := m.Resolve("secret/data/team-a/prod/*"); ok || category != CategoryCrossMountScope {
		t.Fatalf("two KV mounts, tree never listed: ok=%v category=%q, want Unmappable/%s", ok, category, CategoryCrossMountScope)
	}
	// One KV mount: there is no other mount to share the scope with.
	single, err := NewPathMapper([]ProjectRef{{ID: 1, Name: "team-a"}}, map[int][]EnvironmentRef{1: {{ID: 11, Name: "prod"}}},
		[]KVMountInfo{{Path: "secret/", KVVersion: 2}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, category, reason, ok := single.Resolve("secret/data/team-a/prod/*")
	if !ok {
		t.Fatalf("single mount: Unmappable %s (%s)", category, reason)
	}
	if want := []string{"secret/team-a/prod/: policy mount"}; !slices.Equal(res.CrossMountEvidence, want) {
		t.Fatalf("evidence = %v, want %v", res.CrossMountEvidence, want)
	}
}

func readPolicy(path string) []healthscan.Policy {
	return []healthscan.Policy{{Name: "team-a-prod-ro", Blocks: []healthscan.PolicyPathBlock{{Path: path, Capabilities: []string{"read"}}}}}
}

func TestBuildPolicyItems_CarriesCrossMountEvidence(t *testing.T) {
	m := crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-b/prod"}}))
	items := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), m)
	if len(items) != 1 || items[0].Outcome != Create || len(items[0].CrossMountEvidence) != 2 || items[0].SourcePolicy != "team-a-prod-ro" {
		t.Fatalf("items = %+v, want one Create with two evidence lines and its source policy", items)
	}
	items = BuildPolicyItems(readPolicy("secret/data/team-b/prod/*"), m)
	if len(items) != 1 || items[0].Category != CategoryCrossMountScope || len(items[0].CrossMountEvidence) != 2 {
		t.Fatalf("items = %+v, want one cross-mount Unmappable that carries its evidence", items)
	}
}

// The plan-time listing is re-checked at apply (Andrei's condition on option c): apply-access
// re-derives the plan, and CrossMountDrift must flag every stanza whose evidence changed, in
// either direction, before anything is written.
func TestCrossMountDrift_PathsAppearBetweenPlanAndApply(t *testing.T) {
	reviewed := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": nil})))
	fresh := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-a/prod"}})))
	drift := CrossMountDrift(reviewed, fresh)
	if len(drift) != 1 || !strings.Contains(drift[0], "policy:team-a-prod-ro path:secret/data/team-a/prod/*") || !strings.Contains(drift[0], "kv1/team-a/prod/: present") {
		t.Fatalf("drift = %v, want one line naming the stanza and the new kv1 paths", drift)
	}
}

func TestCrossMountDrift_PathsRemovedBetweenPlanAndApply(t *testing.T) {
	reviewed := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-a/prod"}})))
	fresh := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": nil})))
	if drift := CrossMountDrift(reviewed, fresh); len(drift) != 1 {
		t.Fatalf("drift = %v, want one line: the reviewed plan saw kv1 paths that are gone now", drift)
	}
}

func TestCrossMountDrift_MountBecomesUnlistable(t *testing.T) {
	reviewed := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": nil})))
	fresh := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, map[string]KVMountListing{"kv1/": {RootListed: false}}))
	if drift := CrossMountDrift(reviewed, fresh); len(drift) != 1 {
		t.Fatalf("drift = %v, want one line", drift)
	}
}

func TestCrossMountDrift_UnrelatedChangeIsNotDrift(t *testing.T) {
	reviewed := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": nil})))
	fresh := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-b/prod", "team-a/dev"}})))
	if drift := CrossMountDrift(reviewed, fresh); len(drift) != 0 {
		t.Fatalf("drift = %v, want none: team-a/prod is still empty on kv1", drift)
	}
}

func TestCrossMountDrift_ReviewedPlanWithoutEvidence(t *testing.T) {
	m := crossMountMapper(t, kvTree(map[string][]string{"kv1/": nil}))
	fresh := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), m)
	reviewed := BuildPolicyItems(readPolicy("secret/data/team-a/prod/*"), m)
	for i := range reviewed {
		reviewed[i].CrossMountEvidence = nil // a plan file written before this check existed.
	}
	if drift := CrossMountDrift(reviewed, fresh); len(drift) != 1 || !strings.Contains(drift[0], "re-run plan-access") {
		t.Fatalf("drift = %v, want one line asking for a fresh plan", drift)
	}
}

// A reviewed grant names its scope: a fresh grant of the same role to the same machine in
// another environment is a different object and must not ride on the reviewed one.
func TestKey_MachineRoleGrantIncludesScope(t *testing.T) {
	a := Item{Kind: KindMachineRoleGrant, ProposedMachineRef: "m", ProposedRoleRef: "vault-migrated-read", ProposedProjectID: 1, ProposedEnvironmentID: 10}
	b := a
	b.ProposedEnvironmentID = 11
	if Key(a) == Key(b) {
		t.Fatalf("Key(%+v) == Key(%+v) = %q: grants in different environments share a key", a, b, Key(a))
	}
	fresh := []Item{{Kind: KindMachineRoleGrant, Outcome: Create, ProposedMachineRef: "m", ProposedRoleRef: "vault-migrated-read", ProposedProjectID: 1, ProposedEnvironmentID: 11}}
	if selected, _ := SelectForApply(fresh, map[string]bool{Key(a): true}); len(selected) != 0 {
		t.Fatalf("selected %+v: a grant reviewed for environment 10 authorised one in environment 11", selected)
	}
}
