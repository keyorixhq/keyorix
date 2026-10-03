package accessplan

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

func TestBuildAppRoleItems_NoMappablePolicies_NoHomelessIdentity(t *testing.T) {
	roles := []healthscan.AppRoleRoleConfig{{Mount: "auth/approle", Name: "ci-deploy", TokenPolicies: []string{"default"}}}
	items := BuildAppRoleItems(roles, nil, testPolicyMapper(t))
	for _, it := range items {
		if it.Kind == KindMachineIdentity {
			t.Fatalf("a role with no mappable grant must never get a machine identity proposed: %+v", it)
		}
	}
}

func TestBuild_DeduplicatesIdenticalUnmappableAcrossRoles(t *testing.T) {
	policies := []healthscan.Policy{{Name: "god-mode", Blocks: []healthscan.PolicyPathBlock{block("*", "sudo")}}}
	roles := []healthscan.AppRoleRoleConfig{
		{Mount: "auth/approle", Name: "role-one", TokenPolicies: []string{"god-mode"}},
		{Mount: "auth/approle", Name: "role-two", TokenPolicies: []string{"god-mode"}},
	}
	plan := Build(BuildInput{Policies: policies, AppRoles: roles}, testPolicyMapper(t), "")
	var sudoCount int
	for _, it := range plan.Items {
		if it.Category == CategorySudo {
			sudoCount++
		}
	}
	if sudoCount != 1 {
		t.Fatalf("got %d sudo Unmappable rows, want 1 deduplicated row even though 2 roles share the same policy", sudoCount)
	}
}

// fakeReader is a KeyorixReader test double: a name is "found" iff it's a key in existing;
// grants/bindings are "has" iff present in grants/bindings.
type fakeReader struct {
	roleDescriptions    map[string]string
	machineDescriptions map[string]string
	grants              map[string]bool
	bindings            map[string]bool
}

func (f *fakeReader) RoleDescriptionByName(_ context.Context, name string) (string, bool, error) {
	d, ok := f.roleDescriptions[name]
	return d, ok, nil
}

func (f *fakeReader) MachineIdentityDescriptionByName(_ context.Context, _ int, name string) (string, bool, error) {
	d, ok := f.machineDescriptions[name]
	return d, ok, nil
}

func (f *fakeReader) MachineHasRoleGrant(_ context.Context, _ int, machineName, roleName string) (bool, error) {
	return f.grants[machineName+"|"+roleName], nil
}

func (f *fakeReader) MachineHasOIDCBinding(_ context.Context, _ int, machineName, issuer, subject string) (bool, error) {
	return f.bindings[machineName+"|"+issuer+"|"+subject], nil
}

func TestReconcile_CreateWhenNothingExists(t *testing.T) {
	items := []Item{{Kind: KindRole, Outcome: Create, ProposedName: "vault-migrated-read", ProvenanceKey: "k1"}}
	reader := &fakeReader{roleDescriptions: map[string]string{}}
	if err := Reconcile(context.Background(), items, reader); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if items[0].Outcome != Create {
		t.Fatalf("outcome = %q, want Create", items[0].Outcome)
	}
}

func TestReconcile_SkipOnProvenanceMatch(t *testing.T) {
	items := []Item{{Kind: KindRole, Outcome: Create, ProposedName: "vault-migrated-read", ProvenanceKey: "k1"}}
	reader := &fakeReader{roleDescriptions: map[string]string{
		"vault-migrated-read": "migrated by keyorix-migrate\n" + FormatProvenanceLine("k1"),
	}}
	if err := Reconcile(context.Background(), items, reader); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if items[0].Outcome != Skip {
		t.Fatalf("outcome = %q, want Skip", items[0].Outcome)
	}
}

func TestReconcile_ConflictOnNameMatchNoProvenance(t *testing.T) {
	items := []Item{{Kind: KindRole, Outcome: Create, ProposedName: "vault-migrated-read", ProvenanceKey: "k1"}}
	reader := &fakeReader{roleDescriptions: map[string]string{"vault-migrated-read": "a hand-made role, nothing to do with migration"}}
	if err := Reconcile(context.Background(), items, reader); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if items[0].Outcome != Conflict || items[0].ConflictReason == "" {
		t.Fatalf("item = %+v, want Conflict with a reason", items[0])
	}
}

func TestReconcile_ConflictOnDifferentProvenance(t *testing.T) {
	items := []Item{{Kind: KindRole, Outcome: Create, ProposedName: "vault-migrated-read", ProvenanceKey: "k1"}}
	reader := &fakeReader{roleDescriptions: map[string]string{
		"vault-migrated-read": FormatProvenanceLine("a-different-key"),
	}}
	if err := Reconcile(context.Background(), items, reader); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if items[0].Outcome != Conflict {
		t.Fatalf("outcome = %q, want Conflict", items[0].Outcome)
	}
}

func TestReconcile_MachineIdentityHomeProjectDerivedFromItsFirstGrant(t *testing.T) {
	items := []Item{
		{Kind: KindMachineIdentity, Outcome: Create, ProposedName: "vault-approle-ci", ProvenanceKey: "m1"},
		{Kind: KindMachineRoleGrant, Outcome: Create, ProposedMachineRef: "vault-approle-ci", ProposedRoleRef: "vault-migrated-read", ProposedProjectID: 7},
	}
	reader := &fakeReader{machineDescriptions: map[string]string{}, grants: map[string]bool{}}
	if err := Reconcile(context.Background(), items, reader); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if items[0].ProposedProjectID != 7 {
		t.Fatalf("machine identity's resolved home project = %d, want 7 (from its grant)", items[0].ProposedProjectID)
	}
}

func TestReconcile_GrantSkippedWhenAlreadyPresent(t *testing.T) {
	items := []Item{
		{Kind: KindMachineRoleGrant, Outcome: Create, ProposedMachineRef: "m", ProposedRoleRef: "r", ProposedProjectID: 1},
	}
	reader := &fakeReader{grants: map[string]bool{"m|r": true}}
	if err := Reconcile(context.Background(), items, reader); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if items[0].Outcome != Skip {
		t.Fatalf("outcome = %q, want Skip", items[0].Outcome)
	}
}

func TestReconcile_PropagatesLookupError(t *testing.T) {
	items := []Item{{Kind: KindRole, Outcome: Create, ProposedName: "x"}}
	reader := &erroringReader{}
	if err := Reconcile(context.Background(), items, reader); err == nil {
		t.Fatal("expected a lookup error to propagate, not be silently absorbed")
	}
}

type erroringReader struct{ fakeReader }

func (e *erroringReader) RoleDescriptionByName(context.Context, string) (string, bool, error) {
	return "", false, errors.New("keyorix unreachable")
}
