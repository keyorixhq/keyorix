package accessplan

import (
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

func testPolicyMapper(t *testing.T) *PathMapper {
	t.Helper()
	m, err := NewPathMapper(
		[]ProjectRef{{ID: 1, Name: "team-a"}},
		map[int][]EnvironmentRef{1: {{ID: 10, Name: "prod"}}},
		[]KVMountInfo{{Path: "secret/", KVVersion: 2}},
		nil,
	)
	if err != nil {
		t.Fatalf("NewPathMapper: %v", err)
	}
	return m
}

func block(path string, caps ...string) healthscan.PolicyPathBlock {
	return healthscan.PolicyPathBlock{Path: path, Capabilities: caps}
}

func TestBuildPolicyItems_ExactReadGrant(t *testing.T) {
	policies := []healthscan.Policy{{Name: "team-a-ro", Blocks: []healthscan.PolicyPathBlock{
		block("secret/data/team-a/prod/db", "read", "list"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1: %+v", len(items), items)
	}
	it := items[0]
	if it.Outcome != Create || it.Kind != KindRole {
		t.Fatalf("item = %+v, want Create/Role", it)
	}
	if it.ProposedProjectID != 1 || it.ProposedEnvironmentID != 10 {
		t.Fatalf("item scope = (%d,%d), want (1,10)", it.ProposedProjectID, it.ProposedEnvironmentID)
	}
	if len(it.ProposedPermissions) != 1 || it.ProposedPermissions[0] != "secrets.read" {
		t.Fatalf("permissions = %v, want [secrets.read]", it.ProposedPermissions)
	}
}

func TestBuildPolicyItems_SudoIsUnmappable(t *testing.T) {
	policies := []healthscan.Policy{{Name: "god-mode", Blocks: []healthscan.PolicyPathBlock{
		block("*", "sudo"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 1 || items[0].Outcome != Unmappable || items[0].Category != CategorySudo {
		t.Fatalf("items = %+v, want one Unmappable/sudo item", items)
	}
}

func TestBuildPolicyItems_TemplatedPathIsUnmappable(t *testing.T) {
	policies := []healthscan.Policy{{Name: "self-service", Blocks: []healthscan.PolicyPathBlock{
		block("secret/data/team-a/{{identity.entity.id}}/*", "read"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 1 || items[0].Outcome != Unmappable || items[0].Category != CategorySentinelOrTemplated {
		t.Fatalf("items = %+v, want one Unmappable/sentinel-or-templated item", items)
	}
}

func TestBuildPolicyItems_DenyOverlapPushesAllowToUnmappable(t *testing.T) {
	policies := []healthscan.Policy{{Name: "scoped", Blocks: []healthscan.PolicyPathBlock{
		block("secret/data/team-a/prod/*", "read"),
		block("secret/data/team-a/prod/super-secret", "deny"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 1 || items[0].Outcome != Unmappable || items[0].Category != CategoryDenyOverlap {
		t.Fatalf("items = %+v, want the allow pushed to Unmappable/deny-overlap", items)
	}
}

func TestBuildPolicyItems_NonOverlappingDenyDoesNotAffectAllow(t *testing.T) {
	policies := []healthscan.Policy{{Name: "scoped", Blocks: []healthscan.PolicyPathBlock{
		block("secret/data/team-a/prod/db", "read"),
		block("secret/data/team-a/prod/unrelated-secret", "deny"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 1 || items[0].Outcome != Create {
		t.Fatalf("items = %+v, want the allow to survive (deny targets a disjoint literal path)", items)
	}
}

func TestBuildPolicyItems_UnresolvedScopeIsUnmappable(t *testing.T) {
	policies := []healthscan.Policy{{Name: "no-such-team", Blocks: []healthscan.PolicyPathBlock{
		block("secret/data/no-such-team/prod/x", "read"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 1 || items[0].Outcome != Unmappable || items[0].Category != CategoryUnresolvedPathScope {
		t.Fatalf("items = %+v, want Unmappable/unresolved-path-scope", items)
	}
}

func TestBuildPolicyItems_SameCapabilitySetReusesOneRoleName(t *testing.T) {
	policies := []healthscan.Policy{{Name: "p", Blocks: []healthscan.PolicyPathBlock{
		block("secret/data/team-a/prod/a", "read"),
		block("secret/data/team-a/prod/b", "read"),
	}}}
	items := BuildPolicyItems(policies, testPolicyMapper(t))
	if len(items) != 2 || items[0].ProposedName != items[1].ProposedName {
		t.Fatalf("items = %+v, want both to propose the same deterministic role name", items)
	}
}
