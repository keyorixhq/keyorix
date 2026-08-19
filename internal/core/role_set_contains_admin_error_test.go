// role_set_contains_admin_error_test.go — regression tests for the
// roleSetContainsAdmin error-swallowing fix, independent of ADR-084.
//
// roleSetContainsAdmin used to treat any GetRoleByName failure — a genuine
// storage error, not just "role not seeded in this deployment" — identically
// via a bare `continue`, silently returning false. At
// requireGlobalAdminToReinstateAdminRoles and requireMachinePrivilegeCeiling,
// that false is the DANGEROUS direction: it skips a privilege-escalation
// ceiling check rather than denying, the same "lookup error indistinguishable
// from a legitimate negative result" shape #G17 fixed for
// enforceProjectMFA/ProjectMFABlocked. These tests force a genuine
// (non-not-found) GetRoleByName error and assert both functions now deny
// rather than silently allow.
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
// a genuine GetRoleByName error (not "not found") while resolving whether the
// set being reinstated contains an admin-tier role, and asserts the
// reinstatement is denied rather than silently allowed.
func TestRequireGlobalAdminToReinstateAdminRoles_StorageErrorFailsClosed(t *testing.T) {
	mockStorage := &MockStorage{}
	for _, name := range adminRoleNames {
		mockStorage.On("GetRoleByName", mock.Anything, name).
			Return(nil, errors.New("connection reset by peer"))
	}

	c := NewKeyorixCore(mockStorage)
	ctx := context.Background()

	err := c.requireGlobalAdminToReinstateAdminRoles(ctx, 1, []uint{42}, "group")
	require.Error(t, err, "a storage error resolving admin-tier membership must deny the reinstatement, not silently allow it")
}

// TestRequireMachinePrivilegeCeiling_StorageErrorFailsClosed forces a genuine
// GetRoleByName error while resolving whether a machine's role set contains an
// admin-tier role, and asserts token issuance is denied rather than silently
// allowed.
func TestRequireMachinePrivilegeCeiling_StorageErrorFailsClosed(t *testing.T) {
	mockStorage := &MockStorage{}
	mockStorage.On("GetMachineRoles", mock.Anything, uint(7)).
		Return([]*models.Role{{ID: 42, Name: "some-custom-role"}}, nil)
	for _, name := range adminRoleNames {
		mockStorage.On("GetRoleByName", mock.Anything, name).
			Return(nil, errors.New("connection reset by peer"))
	}

	c := NewKeyorixCore(mockStorage)
	ctx := context.Background()

	err := c.requireMachinePrivilegeCeiling(ctx, 1, 7)
	require.Error(t, err, "a storage error resolving the machine's admin-tier membership must deny token issuance, not silently allow it")
}
