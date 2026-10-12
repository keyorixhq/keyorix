package accessplan

import (
	"context"
	"testing"
)

// A resumed apply-access run: the earlier run created the role and the machine identity, then
// was killed before the grant. The fresh plan says Skip, Skip, Create(grant). The grant must
// attach to the EXISTING parents, not fail with "parent was not created in this run".
func TestSelectForApply_ResumedRunGrantsToExistingParents(t *testing.T) {
	fresh := []Item{
		{Kind: KindRole, Outcome: Skip, ProposedName: "vault-migrated-read", ExistingID: 42},
		{Kind: KindMachineIdentity, Outcome: Skip, ProposedName: "vault-approle-ci", ExistingID: 7},
		{Kind: KindMachineRoleGrant, Outcome: Create, ProposedMachineRef: "vault-approle-ci", ProposedRoleRef: "vault-migrated-read"},
	}
	reviewed := map[string]bool{}
	for _, it := range fresh {
		reviewed[Key(it)] = true // the original plan had all three as Create.
	}
	selected, warnings := SelectForApply(fresh, reviewed)
	results := Apply(context.Background(), selected, &fakeWriter{})
	var grant *ApplyResult
	for i := range results {
		if results[i].Item.Kind == KindMachineRoleGrant {
			grant = &results[i]
		}
	}
	if grant == nil || !grant.Ran || grant.Error != "" {
		t.Fatalf("resumed grant must run against the existing parents, got %+v (warnings %v)", grant, warnings)
	}
}

// A Skip item seeds ids only; an unreviewed Create item is never selected.
func TestSelectForApply_NeverSelectsUnreviewedCreate(t *testing.T) {
	fresh := []Item{
		{Kind: KindRole, Outcome: Create, ProposedName: "not-reviewed"},
		{Kind: KindRole, Outcome: Create, ProposedName: "reviewed"},
	}
	selected, _ := SelectForApply(fresh, map[string]bool{Key(fresh[1]): true})
	if len(selected) != 1 || selected[0].ProposedName != "reviewed" {
		t.Fatalf("only the reviewed Create item may be selected, got %+v", selected)
	}
}
