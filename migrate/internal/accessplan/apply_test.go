package accessplan

import (
	"context"
	"errors"
	"testing"
)

// fakeWriter is a KeyorixWriter test double tracking every call it made, for assertions, and
// returning deterministic, incrementing ids.
type fakeWriter struct {
	nextID         int
	createdRoles   []string
	createdMachine []string
	issued         []int
	grants         [][3]int // projectID, machineID, roleID
	bindings       []string // "machineID:issuer:subject"

	failIssue      bool
	failCreateRole bool
}

func (f *fakeWriter) CreateRole(_ context.Context, name, _ string, _ []string) (int, error) {
	if f.failCreateRole {
		return 0, errors.New("create role failed")
	}
	f.nextID++
	f.createdRoles = append(f.createdRoles, name)
	return f.nextID, nil
}

func (f *fakeWriter) CreateMachineIdentity(_ context.Context, _ int, name, _, _ string) (int, error) {
	f.nextID++
	f.createdMachine = append(f.createdMachine, name)
	return f.nextID, nil
}

func (f *fakeWriter) IssueMachineCredential(_ context.Context, _, machineID int, _ string) (string, error) {
	if f.failIssue {
		return "", errors.New("issue failed")
	}
	f.issued = append(f.issued, machineID)
	return "kx_machine_fake_token", nil
}

func (f *fakeWriter) GrantMachineRole(_ context.Context, projectID, _, machineID, roleID int) error {
	f.grants = append(f.grants, [3]int{projectID, machineID, roleID})
	return nil
}

func (f *fakeWriter) CreateOIDCBinding(_ context.Context, _, machineID int, issuer, subject string) error {
	f.bindings = append(f.bindings, fmtBinding(machineID, issuer, subject))
	return nil
}

func fmtBinding(machineID int, issuer, subject string) string {
	return issuer + "|" + subject + "|" + string(rune('0'+machineID))
}

func TestApply_RoleThenMachineThenGrant(t *testing.T) {
	items := []Item{
		{Kind: KindRole, Outcome: Create, ProposedName: "vault-migrated-read", ProposedPermissions: []string{"secrets.read"}, ProvenanceKey: "r1"},
		{Kind: KindMachineIdentity, Outcome: Create, ProposedName: "vault-approle-ci", ProposedIdentityType: "service", ProvenanceKey: "m1"},
		{Kind: KindMachineRoleGrant, Outcome: Create, ProposedRoleRef: "vault-migrated-read", ProposedMachineRef: "vault-approle-ci", ProposedProjectID: 1},
	}
	w := &fakeWriter{}
	results := Apply(context.Background(), items, w)
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("unexpected error on %s %s: %s", r.Item.Kind, r.Item.SourceRef, r.Error)
		}
		if !r.Ran {
			t.Fatalf("expected %s to run: %+v", r.Item.Kind, r)
		}
	}
	if len(w.createdRoles) != 1 || len(w.createdMachine) != 1 || len(w.issued) != 1 || len(w.grants) != 1 {
		t.Fatalf("writer calls = %+v", w)
	}
	if results[1].Credential != "kx_machine_fake_token" {
		t.Fatalf("expected the machine identity's ApplyResult to carry the issued credential, got %+v", results[1])
	}
}

func TestApply_DeduplicatesSameRoleNameWithinOneRun(t *testing.T) {
	roleItem := Item{Kind: KindRole, Outcome: Create, ProposedName: "vault-migrated-read", ProposedPermissions: []string{"secrets.read"}}
	items := []Item{roleItem, roleItem} // two AppRole roles independently proposing the same capability set
	w := &fakeWriter{}
	results := Apply(context.Background(), items, w)
	if len(w.createdRoles) != 1 {
		t.Fatalf("CreateRole called %d times, want 1 (same proposed name)", len(w.createdRoles))
	}
	if results[0].Ran != true || results[1].Ran != false {
		t.Fatalf("results = %+v, want first Ran=true, second Ran=false", results)
	}
}

func TestApply_SkipSeedsExistingIDForLaterGrant(t *testing.T) {
	items := []Item{
		{Kind: KindRole, Outcome: Skip, ProposedName: "vault-migrated-read", ExistingID: 42},
		{Kind: KindMachineIdentity, Outcome: Skip, ProposedName: "vault-approle-ci", ExistingID: 7},
		{Kind: KindMachineRoleGrant, Outcome: Create, ProposedRoleRef: "vault-migrated-read", ProposedMachineRef: "vault-approle-ci", ProposedProjectID: 1},
	}
	w := &fakeWriter{}
	results := Apply(context.Background(), items, w)
	if len(w.grants) != 1 || w.grants[0] != [3]int{1, 7, 42} {
		t.Fatalf("grants = %+v, want [[1 7 42]] (a resumed run must grant against the ALREADY-EXISTING ids, never create new ones)", w.grants)
	}
	if results[2].Error != "" {
		t.Fatalf("unexpected error: %s", results[2].Error)
	}
}

func TestApply_GrantSkippedWhenParentNeverCreated(t *testing.T) {
	items := []Item{
		{Kind: KindMachineRoleGrant, Outcome: Create, ProposedRoleRef: "no-such-role", ProposedMachineRef: "no-such-machine", ProposedProjectID: 1},
	}
	w := &fakeWriter{}
	results := Apply(context.Background(), items, w)
	if results[0].Ran || results[0].Error == "" {
		t.Fatalf("expected a not-run result with an explanatory error, got %+v", results[0])
	}
	if len(w.grants) != 0 {
		t.Fatal("GrantMachineRole must never be called for an unresolved parent")
	}
}

func TestApply_IssueCredentialFailureStillReportsAnError(t *testing.T) {
	items := []Item{{Kind: KindMachineIdentity, Outcome: Create, ProposedName: "vault-approle-ci"}}
	w := &fakeWriter{failIssue: true}
	results := Apply(context.Background(), items, w)
	if results[0].Error == "" || results[0].Credential != "" {
		t.Fatalf("expected an error and no credential, got %+v", results[0])
	}
	if len(w.createdMachine) != 1 {
		t.Fatal("CreateMachineIdentity must still have been called before the credential-issue failure")
	}
}

func TestApply_NonCreateOutcomesNeverCallTheWriter(t *testing.T) {
	items := []Item{
		{Kind: KindRole, Outcome: Conflict, ProposedName: "x"},
		{Kind: KindRole, Outcome: Unmappable, ProposedName: "y"},
	}
	w := &fakeWriter{}
	results := Apply(context.Background(), items, w)
	for _, r := range results {
		if r.Ran {
			t.Fatalf("a Conflict/Unmappable item must never run: %+v", r)
		}
	}
	if len(w.createdRoles) != 0 {
		t.Fatal("CreateRole must never be called for Conflict/Unmappable items")
	}
}
