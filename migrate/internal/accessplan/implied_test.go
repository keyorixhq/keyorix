package accessplan

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// secrets.read implies list (ask rd-smt-fix-secretsread-implies-list, option a with Andrei's
// condition): Keyorix's secrets.read also lists secret names and reads version metadata, which
// Vault grants separately. The plan must report, per policy, every migrated grant that adds
// this. The two real cases are the ones RD-SMT-SPIKE-1's z3 check still flags after the
// scope-widening fix (journey4-n4-readonly, testbed-approle-migrator).

// sourceHCL returns hcl after checking that file (relative to the repo root) still contains
// literal, so the fixtures below cannot drift from the real policies.
func sourceHCL(t *testing.T, file, literal, hcl string) string {
	t.Helper()
	raw, err := os.ReadFile("../../../" + file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	if !strings.Contains(string(raw), literal) {
		t.Fatalf("%s no longer contains %q: update this fixture to the real policy", file, literal)
	}
	return hcl
}

func impliedFor(t *testing.T, items []Item, policy string) ImpliedAccessPolicy {
	t.Helper()
	for _, p := range ImpliedAccessPolicies(items) {
		if p.Policy == policy {
			return p
		}
	}
	t.Fatalf("ImpliedAccessPolicies(%d items) does not list policy %q: %+v", len(items), policy, ImpliedAccessPolicies(items))
	return ImpliedAccessPolicy{}
}

func TestImpliedAccess_ReportListsJourney4AndTestbedMigrator(t *testing.T) {
	both := []string{ImpliedListNames, ImpliedReadVersionMetadata}

	// journey4-n4-readonly: scripts/e2e/journeys/journey4_vault_migrate_test.go, mapped with the
	// --path-map that matches journey 4's --vault-path n4-team import.
	n4 := sourceHCL(t, "scripts/e2e/journeys/journey4_vault_migrate_test.go",
		`path "secret/data/n4-team/*" { capabilities = ["read", "list"] }`,
		`path "secret/data/n4-team/*" { capabilities = ["read", "list"] }`)
	m4, err := NewPathMapper([]ProjectRef{{ID: 1, Name: "n4-project"}}, map[int][]EnvironmentRef{1: {{ID: 11, Name: "production"}}},
		[]KVMountInfo{{Path: "secret/", KVVersion: 2}}, []string{"secret/data/n4-team=1:11"})
	if err != nil {
		t.Fatal(err)
	}
	items := BuildPolicyItems([]healthscan.Policy{{Name: "n4-readonly", Blocks: healthscan.ParsePolicyHCL(n4)}}, m4)
	got := impliedFor(t, items, "n4-readonly")
	if !slices.Equal(got.Access, both) || !slices.Equal(got.Paths, []string{"secret/data/n4-team/*"}) {
		t.Fatalf("n4-readonly: %+v, want access %v on secret/data/n4-team/*", got, both)
	}

	// testbed-approle-migrator: scripts/vault-migration-testbed/seed.sh, AppRole mig1-migrator
	// holding mig1-glob-readonly, with the --path-map TestAccessEquivalence uses.
	mig := sourceHCL(t, "scripts/vault-migration-testbed/seed.sh",
		`path \"secret/data/*\" { capabilities = [\"read\",\"list\"] }`,
		`path "secret/data/*" { capabilities = ["read","list"] }`)
	mt, err := NewPathMapper([]ProjectRef{{ID: 1, Name: "mig1-access-equiv"}}, map[int][]EnvironmentRef{1: {{ID: 11, Name: "production"}}},
		[]KVMountInfo{{Path: "secret/", KVVersion: 2}, {Path: "team-b/", KVVersion: 2}, {Path: "kv1-legacy/", KVVersion: 1}}, []string{"secret/data=1:11"})
	if err != nil {
		t.Fatal(err)
	}
	plan := Build(BuildInput{
		Policies: []healthscan.Policy{{Name: "mig1-glob-readonly", Blocks: healthscan.ParsePolicyHCL(mig)}},
		AppRoles: []healthscan.AppRoleRoleConfig{{Mount: "approle/", Name: "mig1-migrator", TokenPolicies: []string{"mig1-glob-readonly"}}},
	}, mt, "")
	got = impliedFor(t, plan.Items, "mig1-glob-readonly")
	if !slices.Equal(got.Access, both) || !slices.Equal(got.Paths, []string{"secret/data/*"}) {
		t.Fatalf("mig1-glob-readonly: %+v, want access %v on secret/data/*", got, both)
	}
}

func impliedAccessOf(t *testing.T, blocks []healthscan.PolicyPathBlock) []string {
	t.Helper()
	m := testMapper(t)
	items := BuildPolicyItems([]healthscan.Policy{{Name: "p", Blocks: blocks}}, m)
	for _, it := range items {
		if it.Outcome == Create && slices.Contains(it.ProposedPermissions, "secrets.read") {
			return it.ImpliedAccess
		}
	}
	t.Fatalf("no secrets.read Create in %+v", items)
	return nil
}

func TestImpliedAccess_MetadataStanzasCoverIt(t *testing.T) {
	data := healthscan.PolicyPathBlock{Path: "secret/data/team-a/prod/*", Capabilities: []string{"read"}}

	// Both list and read on the matching metadata/ subtree: nothing implied.
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{data, {Path: "secret/metadata/team-a/prod/*", Capabilities: []string{"read", "list"}}}); len(got) != 0 {
		t.Fatalf("implied = %v, want none: Vault already grants names and metadata", got)
	}
	// A wider metadata stanza in another policy of the same role covers it too.
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{data, {Path: "secret/metadata/*", Capabilities: []string{"list", "read"}}}); len(got) != 0 {
		t.Fatalf("implied = %v, want none", got)
	}
	// list only: version metadata is still implied.
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{data, {Path: "secret/metadata/team-a/prod/*", Capabilities: []string{"list"}}}); !slices.Equal(got, []string{ImpliedReadVersionMetadata}) {
		t.Fatalf("implied = %v, want [%s]", got, ImpliedReadVersionMetadata)
	}
	// A narrower metadata stanza does not cover the whole scope.
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{data, {Path: "secret/metadata/team-a/prod/db/*", Capabilities: []string{"list", "read"}}}); len(got) != 2 {
		t.Fatalf("implied = %v, want both", got)
	}
	// "list" on data/ lists nothing in KV v2 (journey 4's shape).
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{{Path: "secret/data/team-a/prod/*", Capabilities: []string{"read", "list"}}}); len(got) != 2 {
		t.Fatalf("implied = %v, want both", got)
	}
	// A deny on the metadata subtree hides names in Vault, whatever else grants them.
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{data,
		{Path: "secret/metadata/*", Capabilities: []string{"list", "read"}},
		{Path: "secret/metadata/team-a/prod/*", Capabilities: []string{"deny"}}}); len(got) != 2 {
		t.Fatalf("implied = %v, want both", got)
	}
}

func TestImpliedAccess_KVv1(t *testing.T) {
	// KV v1 lists on the secret path itself and has no version metadata at all.
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{{Path: "kv1/team-b/prod/*", Capabilities: []string{"read", "list"}}}); !slices.Equal(got, []string{ImpliedReadVersionMetadata}) {
		t.Fatalf("implied = %v, want [%s]", got, ImpliedReadVersionMetadata)
	}
	if got := impliedAccessOf(t, []healthscan.PolicyPathBlock{{Path: "kv1/team-b/prod/*", Capabilities: []string{"read"}}}); len(got) != 2 {
		t.Fatalf("implied = %v, want both", got)
	}
}
