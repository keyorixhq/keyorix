package accessplan

import (
	"slices"
	"strings"
	"testing"
)

// A --path-map scope is also named by the default convention: kv1/team-a/dev/x lands in
// project team-a / environment dev by name, which is the scope "secret/data=1:10" maps the
// secret mount into. ADR-114 used to leave this uncovered ("the override declares the scope's
// content"), but plan-access never sees what the operator imported where, and it now lists the
// other mounts: a scope is only equivalent to the Vault policy when the listed paths prove no
// other mount's paths land in it. testMapper's team-a is project 1, dev is environment 10.

// The name matches, the mount differs: not equivalent, and the answer names the counterexample.
func TestPathMapScope_OtherMountHoldsSameNameIsNotEquivalent(t *testing.T) {
	m := testMapper(t, "secret/data=1:10")
	m.SetKVTree(kvTree(map[string][]string{"secret/": {"payments/db"}, "kv1/": {"team-a/dev"}}))

	it := buildOne(t, m, "secret/data/*", "read", "list")
	requireUnmappable(t, it, CategoryCrossMountScope)

	for _, want := range []string{
		"kv1/team-a/dev/: present", // the counterexample: the path the grant would also reach
		"--path-map",               // and the way out
		`"secret/data/*"`, `project "team-a"`, `"dev"`,
	} {
		if !strings.Contains(it.Reason, want) {
			t.Errorf("reason %q does not contain %q", it.Reason, want)
		}
	}
	if !slices.Contains(it.CrossMountEvidence, "kv1/team-a/dev/: present") ||
		!slices.Contains(it.CrossMountEvidence, "secret/team-a/dev/: policy mount") {
		t.Errorf("evidence %v must record what each mount held", it.CrossMountEvidence)
	}
}

func TestPathMapScope_NothingByNameInOtherMounts_StaysEquivalent(t *testing.T) {
	cases := map[string]map[string][]string{
		"the other mount is empty":            {"secret/": {"payments/db"}, "kv1/": nil},
		"the other mount holds another env":   {"kv1/": {"team-a/prod"}},
		"the other mount holds another proj":  {"kv1/": {"team-b/dev"}},
		"the other mount names it as a leaf":  {"kv1/": {"team-a"}}, // a secret called team-a holds nothing below it
		"the policy mount holds the same too": {"secret/": {"team-a/dev"}, "kv1/": nil},
	}
	for name, tree := range cases {
		t.Run(name, func(t *testing.T) {
			m := testMapper(t, "secret/data=1:10")
			m.SetKVTree(kvTree(tree))
			it := buildOne(t, m, "secret/data/*", "read", "list")
			requireCreate(t, it, 1, 10)
			if len(it.CrossMountEvidence) != 2 {
				t.Errorf("evidence %v must record what each of the two mounts held", it.CrossMountEvidence)
			}
		})
	}
}

// A project-wide override (environment 0) covers every environment: any same-named project
// directory in another mount lands in it.
func TestPathMapScope_ProjectWideOverride(t *testing.T) {
	m := testMapper(t, "secret/data=1:0")
	m.SetKVTree(kvTree(map[string][]string{"kv1/": {"team-a/prod"}}))
	requireUnmappable(t, buildOne(t, m, "secret/data/*", "read", "list"), CategoryCrossMountScope)

	m.SetKVTree(kvTree(map[string][]string{"kv1/": {"team-b/prod"}}))
	requireCreate(t, buildOne(t, m, "secret/data/*", "read", "list"), 1, 0)
}

// Fail closed: a mount the listing could not read may hold the path.
func TestPathMapScope_UnlistedMountFailsClosed(t *testing.T) {
	m := testMapper(t, "secret/data=1:10")
	tree := kvTree(map[string][]string{"secret/": nil})
	tree["kv1/"] = KVMountListing{RootListed: false}
	m.SetKVTree(tree)
	it := buildOne(t, m, "secret/data/*", "read", "list")
	requireUnmappable(t, it, CategoryCrossMountScope)
	if !strings.Contains(it.Reason, "kv1/team-a/dev/: not listed") {
		t.Errorf("reason %q must name the mount it could not list", it.Reason)
	}

	// The tree was never listed at all (two KV mounts): nothing proves the other is empty.
	m.SetKVTree(nil)
	requireUnmappable(t, buildOne(t, m, "secret/data/*", "read", "list"), CategoryCrossMountScope)
}

// The way out the reason offers works: once --path-map sends the other mount's team-a/ to a
// different scope, its paths no longer land here by name, and the listing says so.
func TestPathMapScope_OtherMountMappedElsewhereIsNotByName(t *testing.T) {
	m := testMapper(t, "secret/data=1:10", "kv1/team-a=2:20")
	m.SetKVTree(kvTree(map[string][]string{"kv1/": {"team-a/dev"}}))
	it := buildOne(t, m, "secret/data/*", "read", "list")
	requireCreate(t, it, 1, 10)
	if !slices.Contains(it.CrossMountEvidence, "kv1/team-a/dev/: mapped by --path-map kv1/team-a") {
		t.Errorf("evidence %v must say which --path-map entry routes the other mount's path", it.CrossMountEvidence)
	}

	// An override that covers only part of the other mount's scope leaves the rest by name.
	m = testMapper(t, "secret/data=1:10", "kv1/team-a/dev/db=2:20")
	m.SetKVTree(kvTree(map[string][]string{"kv1/": {"team-a/dev"}}))
	requireUnmappable(t, buildOne(t, m, "secret/data/*", "read", "list"), CategoryCrossMountScope)
}

// The policy's own mount is not exempt: --path-map secret/data/legacy=1:10 takes only
// secret/data/legacy/ into team-a/dev, and secret/team-a/dev/x (outside secret/data/legacy/*)
// still lands there by name. The evidence must not call that directory "policy mount", which
// would tell the plan reviewer the policy covers it.
func TestPathMapScope_PolicyMountOutsideThePolicyIsNotEquivalent(t *testing.T) {
	m := testMapper(t, "secret/data/legacy=1:10")
	m.SetKVTree(kvTree(map[string][]string{"secret/": {"legacy/x", "team-a/dev"}, "kv1/": nil}))
	it := buildOne(t, m, "secret/data/legacy/*", "read", "list")
	requireUnmappable(t, it, CategoryCrossMountScope)
	const want = "secret/team-a/dev/: present (policy mount, outside the policy)"
	if !strings.Contains(it.Reason, want) || !slices.Contains(it.CrossMountEvidence, want) {
		t.Errorf("reason %q / evidence %v must name %q", it.Reason, it.CrossMountEvidence, want)
	}
	if slices.Contains(it.CrossMountEvidence, "secret/team-a/dev/: policy mount") {
		t.Errorf("evidence %v labels a directory the policy does not cover as the policy mount", it.CrossMountEvidence)
	}

	// Fail closed: the own mount could not be listed at the project level.
	tree := kvTree(map[string][]string{"kv1/": nil})
	tree["secret/"] = KVMountListing{RootListed: true, Projects: map[string]KVProjectListing{"team-a": {Listed: false}}}
	m.SetKVTree(tree)
	requireUnmappable(t, buildOne(t, m, "secret/data/legacy/*", "read", "list"), CategoryCrossMountScope)
}

func TestPathMapScope_PolicyMountOutsideThePolicy_Controls(t *testing.T) {
	// Nothing by name on the own mount: equivalent.
	m := testMapper(t, "secret/data/legacy=1:10")
	m.SetKVTree(kvTree(map[string][]string{"secret/": {"legacy/x", "team-a/prod"}, "kv1/": nil}))
	it := buildOne(t, m, "secret/data/legacy/*", "read", "list")
	requireCreate(t, it, 1, 10)
	if !slices.Contains(it.CrossMountEvidence, "secret/team-a/dev/: absent (policy mount, outside the policy)") {
		t.Errorf("evidence %v must record the own mount's directory outside the policy", it.CrossMountEvidence)
	}

	// Another --path-map entry routes the own mount's team-a/dev/ elsewhere: not by name.
	m = testMapper(t, "secret/data/legacy=1:10", "secret/data/team-a=2:20")
	m.SetKVTree(kvTree(map[string][]string{"secret/": {"legacy/x", "team-a/dev"}, "kv1/": nil}))
	requireCreate(t, buildOne(t, m, "secret/data/legacy/*", "read", "list"), 1, 10)

	// A policy that covers the own mount's directory keeps "policy mount".
	m = testMapper(t, "secret/data=1:10")
	m.SetKVTree(kvTree(map[string][]string{"secret/": {"team-a/dev"}, "kv1/": nil}))
	it = buildOne(t, m, "secret/data/*", "read", "list")
	requireCreate(t, it, 1, 10)
	if !slices.Contains(it.CrossMountEvidence, "secret/team-a/dev/: policy mount") {
		t.Errorf("evidence %v: the policy covers secret/data/team-a/dev/", it.CrossMountEvidence)
	}
}

// A single KV mount has no other mount to share the scope with, with or without a listing.
func TestPathMapScope_SingleMountNeedsNoListing(t *testing.T) {
	m, err := NewPathMapper([]ProjectRef{{ID: 1, Name: "team-a"}}, map[int][]EnvironmentRef{1: {{ID: 10, Name: "dev"}}},
		[]KVMountInfo{{Path: "secret/", KVVersion: 2}}, []string{"secret/data=1:10"})
	if err != nil {
		t.Fatal(err)
	}
	requireCreate(t, buildOne(t, m, "secret/data/*", "read", "list"), 1, 10)
}

// apply-access re-derives the plan and refuses when the evidence moved: that covers --path-map
// stanzas now that they carry evidence.
func TestPathMapScope_ApplyRefusesWhenTheOtherMountChanged(t *testing.T) {
	build := func(kv1 []string) []Item {
		m := testMapper(t, "secret/data=1:10")
		m.SetKVTree(kvTree(map[string][]string{"kv1/": kv1}))
		return []Item{buildOne(t, m, "secret/data/*", "read", "list")}
	}
	reviewed, fresh := build(nil), build([]string{"team-a/dev"})
	reviewed[0].Kind, fresh[0].Kind = KindRole, KindRole
	drift := CrossMountDrift(reviewed, fresh)
	if len(drift) != 1 || !strings.Contains(drift[0], "kv1/team-a/dev/: present") {
		t.Fatalf("drift = %v, want one line naming the new kv1/team-a/dev/ path", drift)
	}
}
