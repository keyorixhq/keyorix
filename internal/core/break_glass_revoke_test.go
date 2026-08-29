// break_glass_revoke_test.go — regression tests for RevokeBreakGlass's handling of
// RemoveUserRole failures (#303): a genuine storage failure removing the emergency
// role assignment must abort the revoke rather than silently proceeding to mark the
// activation "revoked" while the live grant survives in user_roles. The companion
// "row already gone" case (already auto-expired, or already removed) must still be
// treated as success.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestActivation() *models.BreakGlassActivation {
	expiresAt := time.Date(2026, 7, 1, 13, 0, 0, 0, time.UTC)
	return &models.BreakGlassActivation{
		ID: 7, ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor",
		State: BreakGlassActive, ExpiresAt: &expiresAt,
	}
}

// TestRevokeBreakGlass_GenuineRoleRemovalFailureAbortsRevoke reproduces #303: a
// genuine storage error (NOT "row not assigned") from RemoveUserRole must propagate
// out of RevokeBreakGlass, and the function must NOT go on to persist the activation
// as revoked. Before the fix, the error was discarded (`_ = c.RemoveUserRole(...)`)
// and the function proceeded unconditionally, leaving the emergency role grant LIVE
// in user_roles while the activation, API response, and audit trail all reported it
// as revoked.
func TestRevokeBreakGlass_GenuineRoleRemovalFailureAbortsRevoke(t *testing.T) {
	mockStorage := new(MockStorage)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: mockStorage, now: func() time.Time { return now }}
	ctx := context.Background()

	activation := newTestActivation()
	mockStorage.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(activation, nil)

	dbErr := errors.New("connection reset by peer")
	mockStorage.On("RemoveRole", mock.Anything, uint(10), uint(3), storage.Scope{ProjectID: 2}).Return(dbErr)

	err := c.RevokeBreakGlass(ctx, 1, 0, 2, 7)
	require.Error(t, err, "a genuine RemoveUserRole failure must abort the revoke")

	// The conditional state transition (and the audit write that follows it) must
	// never be reached: no expectation was set for either, so RevokeBreakGlassActivation
	// or LogAuditEvent being called would fail this test (mock panics on an
	// unexpected call, or AssertExpectations below would report an extra call).
	mockStorage.AssertNotCalled(t, "RevokeBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mockStorage.AssertExpectations(t)
}

// TestRevokeBreakGlass_AlreadyGoneRoleRemovalIsNotAFailure is the companion half of
// #303: RemoveUserRole's own "row not found" case (the grant already auto-expired,
// or a racing revoke already removed it) must still be treated as success, not a
// hard failure that blocks the revoke.
func TestRevokeBreakGlass_AlreadyGoneRoleRemovalIsNotAFailure(t *testing.T) {
	mockStorage := new(MockStorage)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: mockStorage, now: func() time.Time { return now }}
	ctx := context.Background()

	activation := newTestActivation()
	mockStorage.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(activation, nil)
	mockStorage.On("RemoveRole", mock.Anything, uint(10), uint(3), storage.Scope{ProjectID: 2}).
		Return(storage.ErrRoleNotAssigned)
	mockStorage.On("RevokeBreakGlassActivation", mock.Anything, uint(7), uint(1), uint(0), now).Return(nil)
	mockStorage.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	err := c.RevokeBreakGlass(ctx, 1, 0, 2, 7)
	require.NoError(t, err, "an already-removed role assignment must not block the revoke")
	mockStorage.AssertExpectations(t)
}
