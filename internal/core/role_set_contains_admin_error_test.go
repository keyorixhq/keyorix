// role_set_contains_admin_error_test.go — regression tests for
// roleSetContainsAdmin's fail-closed behavior on a genuine resolution error.
// Originally written against the name-based implementation (a GetRoleByName
// failure that wasn't "not found"); roleSetContainsAdmin now resolves by
// structural flag (ADR-084, storage.RoleSetBypassesPermissionChecks) instead,
// but the property under test is unchanged: a real storage error must
// propagate and deny, not be silently swallowed into "false". At
// requireGlobalAdminToReinstateAdminRoles and requireMachinePrivilegeCeiling,
// a swallowed "false" is the DANGEROUS direction — it skips a
// privilege-escalation ceiling check rather than denying, the same "lookup
// error indistinguishable from a legitimate negative result" shape #G17 fixed
// for enforceProjectMFA/ProjectMFABlocked.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestRequireGlobalAdminToReinstateAdminRoles_StorageErrorFailsClosed forces
// a genuine resolution error while resolving whether the set being
// reinstated contains an admin-tier role, and asserts the reinstatement is
// denied rather than silently allowed.
func TestRequireGlobalAdminToReinstateAdminRoles_StorageErrorFailsClosed(t *testing.T) {
	mockStorage := &MockStorage{}
	mockStorage.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).
		Return(false, errors.New("connection reset by peer"))

	c := NewKeyorixCore(mockStorage)
	ctx := context.Background()

	err := c.requireGlobalAdminToReinstateAdminRoles(ctx, 1, []uint{42}, "group")
	require.Error(t, err, "a storage error resolving admin-tier membership must deny the reinstatement, not silently allow it")
}

// TestRequireMachinePrivilegeCeiling_StorageErrorFailsClosed forces a genuine
// resolution error while resolving whether a machine's role set contains an
// admin-tier role, and asserts token issuance is denied rather than silently
// allowed.
func TestRequireMachinePrivilegeCeiling_StorageErrorFailsClosed(t *testing.T) {
	mockStorage := &MockStorage{}
	mockStorage.On("GetMachineRoles", mock.Anything, uint(7)).
		Return([]*models.Role{{ID: 42, Name: "some-custom-role"}}, nil)
	mockStorage.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).
		Return(false, errors.New("connection reset by peer"))

	c := NewKeyorixCore(mockStorage)
	ctx := context.Background()

	err := c.requireMachinePrivilegeCeiling(ctx, ActorTypeUser, 1, 0, 7)
	require.Error(t, err, "a storage error resolving the machine's admin-tier membership must deny token issuance, not silently allow it")
}
