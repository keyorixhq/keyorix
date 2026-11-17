package authzdiff

import (
	"context"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// HF2 §6 ii: the seeded fixture gives every target machine exactly ONE role at
// ONE project scope (project_auditor at its own project), so the model's
// per-scope coverage loop in machineCovers — and the product's matching
// requireActorHoldsTargetPermissions, which authorises each target permission at
// the scope the target holds it — is never exercised with a target that spans
// MORE than one scope.
//
// The seeded template is deliberately NOT changed to a multi-scope target:
// doing so would alter the privilege-ceiling coverage requirement for every
// caller on machine.token.issue across the whole sweep, shifting the fix-3993 /
// fix-4332 plant floors and breaking TestModel_MachineTokenIssue_UserCeiling's
// single-scope rows. Instead this test builds a multi-scope target on its own
// fresh leg and checks that the model and the product (core) agree on it — the
// cheap, isolated way to exercise the gap.
//
// Setup: target machine A, which already holds project_auditor@A, is given a
// SECOND role at project B (project_viewer@B = {secrets.read, users.read}). A
// caller may now mint its token only by covering BOTH scopes.
func TestModel_MachineCovers_MultiScopeTarget(t *testing.T) {
	specs := withDerived(t, ops())
	i := slices.IndexFunc(specs, func(s opSpec) bool { return s.name == "machine.token.issue" })
	if i < 0 {
		t.Fatal("machine.token.issue op not found")
	}
	spec := specs[i]

	lg := newLeg(t, layerCore)
	defer lg.close()
	lg.applyVariation(t, defaultVariation)
	fx := lg.fx

	// target A spans two scopes: project_auditor@A (seeded) + project_viewer@B.
	if e := lg.db.Create(&models.MachineIdentityRole{
		MachineIdentityID: fx.A.machineID,
		RoleID:            fx.roleIDs["project_viewer"],
		ProjectID:         fx.B.projectID,
	}).Error; e != nil {
		t.Fatalf("seed second-scope machine role: %v", e)
	}

	m := model{lg.db}
	req := spec.req(fx, tA, 0) // tokenForMachineID = fx.A.machineID, gate roles.assign@A

	// Sanity: machineCovers now reads roles at two distinct scopes for the target.
	grants := m.grants(&principal{machineID: fx.A.machineID})
	scopes := map[uint]bool{}
	for _, g := range grants {
		scopes[g.projectID] = true
	}
	if len(scopes) < 2 {
		t.Fatalf("target machine should hold roles at >= 2 scopes, got %d (%v)", len(scopes), scopes)
	}

	// pkGlobalAdmin covers every permission at every scope -> model allows and the
	// product mints the token.
	admin := fx.principals[pkGlobalAdmin]
	if !m.machineCovers(admin, fx.A.machineID) {
		t.Errorf("global admin must cover a multi-scope target (holds every perm at every scope)")
	}
	if !m.allowed(admin, req) {
		t.Errorf("model denies global admin on a multi-scope target; want allowed")
	}
	if _, err := lg.c.IssueMachineToken(context.Background(), fx.A.projectID, fx.A.machineID,
		admin.userID, core.IssueMachineTokenParams{Name: "ms-admin"}); err != nil {
		t.Errorf("core denies global admin on a multi-scope target: %v", err)
	}

	// pkProjAdmin holds project_admin@A only: it covers project_auditor@A (bypass
	// at A) but holds NO role at B, so it does NOT cover project_viewer@B. The
	// per-scope loop must refuse it — the single-scope fixture could never show
	// this, because at A alone project_admin@A covers the target fully.
	padmin := fx.principals[pkProjAdmin]
	if m.machineCovers(padmin, fx.A.machineID) {
		t.Errorf("project_admin@A must NOT cover a target that also holds a role at B (no authority at B)")
	}
	if m.allowed(padmin, req) {
		t.Errorf("model allows project_admin@A on a multi-scope target; want denied (missing B coverage)")
	}
	// Product agreement: core must also refuse the mint (the privilege ceiling
	// authorises each target permission at the scope it is held; B is unmet).
	_, err := lg.c.IssueMachineToken(context.Background(), fx.A.projectID, fx.A.machineID,
		padmin.userID, core.IssueMachineTokenParams{Name: "ms-padmin"})
	if err == nil {
		t.Errorf("core allows project_admin@A to mint a token for a target holding a role at B; " +
			"want denied — the model and the product must agree on multi-scope coverage")
	}
}
