// sod_machine_grant_violation_test.go extends requireMachineGrantNoSoDViolation's
// coverage (sod.go) past its early-return branches (already covered by
// core_s30_test.go: list-policies error, no policies, GetRole error, admin-role
// bypass). Untested before this file: the role's OWN permission-lookup error,
// the machine's-other-roles lookup error, the held-permissions accumulation
// loop's own per-role error, the actual violation-detected rejection, and the
// no-violation success path -- i.e. the entire reason this check exists.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRequireMachineGrantNoSoDViolation_AddingRolePermissionsError(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1, Name: "split-duty", PermissionA: "secrets.write", PermissionB: "secrets.delete"}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(10)).Return(&models.Role{ID: 10, Name: "custom_writer"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(10)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 10)
	require.Error(t, err)
}

func TestRequireMachineGrantNoSoDViolation_NoAddedPermissions_NoOp(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1, Name: "split-duty", PermissionA: "secrets.write", PermissionB: "secrets.delete"}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(11)).Return(&models.Role{ID: 11, Name: "empty_role"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(11)).Return([]*models.Permission{}, nil)
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 11)
	require.NoError(t, err)
	ms.AssertNotCalled(t, "GetMachineRoles", mock.Anything, mock.Anything)
}

func TestRequireMachineGrantNoSoDViolation_MachineRolesError(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1, Name: "split-duty", PermissionA: "secrets.write", PermissionB: "secrets.delete"}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(12)).Return(&models.Role{ID: 12, Name: "custom_writer"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(12)).Return([]*models.Permission{{ID: 1, Name: "secrets.write"}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 12)
	require.Error(t, err)
}

func TestRequireMachineGrantNoSoDViolation_HeldRolePermissionsError(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1, Name: "split-duty", PermissionA: "secrets.write", PermissionB: "secrets.delete"}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(13)).Return(&models.Role{ID: 13, Name: "custom_writer"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(13)).Return([]*models.Permission{{ID: 1, Name: "secrets.write"}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 20, Name: "other_role"}}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(20)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 13)
	require.Error(t, err)
}

// TestRequireMachineGrantNoSoDViolation_ViolationDetected_Blocked is the
// invariant this whole check exists for: a machine that already holds
// secrets.delete (via an unrelated existing role) must be rejected when
// granted a role that adds secrets.write, since the pair completes the SoD
// policy.
func TestRequireMachineGrantNoSoDViolation_ViolationDetected_Blocked(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1, Name: "split-duty", PermissionA: "secrets.write", PermissionB: "secrets.delete"}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(14)).Return(&models.Role{ID: 14, Name: "writer_role"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(14)).Return([]*models.Permission{{ID: 1, Name: "secrets.write"}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 21, Name: "deleter_role"}}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(21)).Return([]*models.Permission{{ID: 2, Name: "secrets.delete"}}, nil)
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 14)
	require.Error(t, err)
	assert.ErrorContains(t, err, "split-duty")
}

// TestRequireMachineGrantNoSoDViolation_NoViolation_Allowed is the success
// path: granting a role that adds a permission with no SoD-conflicting
// counterpart already held must succeed.
func TestRequireMachineGrantNoSoDViolation_NoViolation_Allowed(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1, Name: "split-duty", PermissionA: "secrets.write", PermissionB: "secrets.delete"}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(15)).Return(&models.Role{ID: 15, Name: "reader_role"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(15)).Return([]*models.Permission{{ID: 3, Name: "secrets.read"}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 22, Name: "another_role"}}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(22)).Return([]*models.Permission{{ID: 4, Name: "projects.read"}}, nil)
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 15)
	require.NoError(t, err)
}
