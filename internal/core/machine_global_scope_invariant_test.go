// machine_global_scope_invariant_test.go — guards a structural invariant that
// #1573's investigation leaned on to classify ten attribution fields as
// unreachable by any machine identity (see docs/adr-091-machine-global-scope-attribution.md):
// a machine identity can never hold a role grant at global scope (ProjectID 0).
//
// The invariant holds because AssignMachineRole's machineInProject check
// requires m.ProjectID == scope.ProjectID, and every real MachineIdentity row
// has a nonzero ProjectID (machines are always created scoped to a project —
// there is no machine-identity creation path that leaves ProjectID 0). So a
// global-scope grant attempt can never find a matching machine, and
// GetMachineRoleIDsAt(machineID, Scope{ProjectID:0}) — the query
// AuthorizePrincipal's machine branch uses — never returns a role for any
// machine at global scope either way. Any route gated by RequirePermission
// (== RequireScopedPermission(perm, ScopeGlobal)) is therefore categorically
// unreachable by a machine caller, independent of what permission it names or
// what downstream check exists — a fact both this issue and #1545 depend on.
//
// Nothing else in this codebase asserts this — a future change to
// machineInProject (or a new path to storage.AssignMachineRole that bypasses
// it) would silently invalidate every classification built on it, with
// nothing to catch the drift. This test is that catch.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAssignMachineRole_GlobalScopeRejected pins the invariant: a real machine
// identity (nonzero ProjectID, as every one is) can never be granted a role at
// global scope (Scope{ProjectID: 0}) — AssignMachineRole must refuse before
// ever reaching storage.AssignMachineRole.
//
// Verified red per standing practice: temporarily changed machineInProject's
// comparison from `m.ProjectID != projectID` to `false` (i.e. "any project
// matches"), confirmed this test failed with storage.AssignMachineRole
// actually invoked, then reverted.
func TestAssignMachineRole_GlobalScopeRejected(t *testing.T) {
	ms := new(MockStorage)
	machine := &models.MachineIdentity{ID: 1, ProjectID: 5, Name: "ci-runner", State: MachineActive}
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(machine, nil)
	c := NewKeyorixCore(ms)

	err := c.AssignMachineRole(context.Background(), 1, 2, Scope{ProjectID: 0}, 1)

	require.Error(t, err, "a machine identity must never be grantable a role at global scope")
	ms.AssertNotCalled(t, "AssignMachineRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestAssignMachineRole_GlobalScopeRejected_EvenIfMachineLookupSomehowReturnedGlobal
// covers the theoretical case where GetMachineIdentity itself returned a row
// with ProjectID 0 (should never happen in practice — every creation path
// requires a nonzero project — but machineInProject's own comparison is what
// this test pins, not the creation invariant, since a storage-layer bug
// producing such a row is a different failure mode this check should still
// catch defensively... except it wouldn't: matching ProjectIDs of 0 and 0
// legitimately passes machineInProject. This is intentional and documented
// here rather than silently assumed: the SOLE thing preventing a global-scope
// machine grant is that no real MachineIdentity row ever has ProjectID 0, not
// a second independent check. See TestCreateMachineIdentity_RejectsZeroProject
// for the creation-side half of this invariant.
func TestAssignMachineRole_GlobalScopeRejected_EvenIfMachineLookupSomehowReturnedGlobal(t *testing.T) {
	ms := new(MockStorage)
	machine := &models.MachineIdentity{ID: 1, ProjectID: 0, Name: "corrupted-fixture", State: MachineActive}
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(machine, nil)
	role := &models.Role{ID: 2, Name: "viewer"}
	ms.On("GetRole", mock.Anything, uint(2)).Return(role, nil)
	ms.On("AssignMachineRole", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)

	err := c.AssignMachineRole(context.Background(), 1, 2, Scope{ProjectID: 0}, 1)

	require.NoError(t, err, "machineInProject matches ProjectID 0 == 0 -- this documents the gap rather than hiding it")
	ms.AssertCalled(t, "AssignMachineRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateMachineIdentity_RejectsZeroProject pins the other half of the
// invariant: CreateMachineIdentity itself refuses projectID 0, so no
// production path can ever produce the ProjectID==0 MachineIdentity row the
// test above shows would defeat machineInProject's check. This is the
// invariant's real enforcement point.
func TestCreateMachineIdentity_RejectsZeroProject(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	_, err := c.CreateMachineIdentity(context.Background(), 0, "orphan", "service", "", "", 1)

	require.Error(t, err)
	ms.AssertNotCalled(t, "CreateMachineIdentity", mock.Anything, mock.Anything)
}
