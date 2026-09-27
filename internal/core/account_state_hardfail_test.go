package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// errAccountStatePersistFailure simulates a storage backend that cannot persist
// account_state at all — a hard, permanent write failure, as opposed to a
// transient one.
var errAccountStatePersistFailure = errors.New("account_state cannot be persisted by this storage backend")

// TestSuspendUser_HardFailsWhenBackendCannotPersistAccountState is the (#454)
// regression for the "explicit security directive" half of the fix: an admin
// suspending a user against a storage backend that can never persist account_state
// must see the call FAIL — never a silent "success" that leaves the account state
// unchanged and the admin believing the suspension took effect.
func TestSuspendUser_HardFailsWhenBackendCannotPersistAccountState(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()

	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, AccountState: AccountActive}, nil)
	// S1 (CLI-split inventory #2012): SuspendUser now calls the admin-rank
	// ceiling first (actor 1 != target 2) — the fixture target holds no role
	// scopes, so the ceiling passes trivially, unchanged from this test's
	// original expectations.
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{}, nil)
	// guardLastAdminDeactivation (#G02) runs first — fixture user holds no
	// roles, so IsGlobalAdmin resolves false and the guard is a no-op.
	store.On("GetUserRoleIDsAt", ctx, uint(2), Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(2), Scope{}).Return([]uint{}, nil)
	store.On("ListSessionTokenHashesForUser", ctx, uint(2)).Return([]string{}, nil)
	// H-2: ListPersonalAccessTokensByUser is called before SetAccountState.
	store.On("ListPersonalAccessTokensByUser", ctx, uint(2)).Return([]*models.PersonalAccessToken{}, nil)
	store.On("SetAccountState", ctx, uint(2), AccountSuspended, mock.Anything).Return(errAccountStatePersistFailure)

	err := c.SuspendUser(ctx, 1, 2)
	require.Error(t, err, "SuspendUser must fail, not silently succeed, when the backend can't persist account_state")
	require.ErrorIs(t, err, errAccountStatePersistFailure)

	// The write must never have escalated to session/PAT revocation on a failed state
	// change (nothing was actually suspended, so nothing should be torn down either).
	store.AssertNotCalled(t, "DeleteSessionsForUserExcept", mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// TestUpdateSCIMUser_HardFailsWhenBackendCannotPersistDeprovision is the (#454)
// regression for UpdateSCIMUser's deactivation path: a SCIM/IdP deprovision under a
// backend that cannot persist account_state must fail closed, not report success
// while the account silently stays reachable.
func TestUpdateSCIMUser_HardFailsWhenBackendCannotPersistDeprovision(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	target := &models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}
	store.On("GetUser", ctx, uint(2)).Return(target, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(2), Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(2), Scope{}).Return([]uint{}, nil)
	store.On("SetAccountState", ctx, uint(2), AccountDeprovisioned, mock.Anything).Return(errAccountStatePersistFailure)

	no := false
	_, err := c.UpdateSCIMUser(ctx, 9, 2, nil, nil, &no)
	require.Error(t, err, "a SCIM deactivation must fail, not silently succeed, when the backend can't persist account_state")
	require.ErrorIs(t, err, errAccountStatePersistFailure)

	// Since SetAccountState is attempted (and fails) BEFORE the generic wire-field
	// write, nothing should have been partially applied either.
	store.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// TestUpdateSCIMUser_NoStateChange_DoesNotConsultSetAccountState confirms the #454
// fix didn't turn every SCIM update into a hard failure: a PATCH that never touches
// account_state (e.g. displayName-only) must still succeed under a backend that can't
// persist account_state, since SetAccountState is only invoked when the state
// actually changes.
func TestUpdateSCIMUser_NoStateChange_DoesNotConsultSetAccountState(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	target := &models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}
	store.On("GetUser", ctx, uint(2)).Return(target, nil)
	store.On("UpdateUserIfActiveStateMatches", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.DisplayName == "Bob Smith"
	}), true).Return(true, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

	name := "Bob Smith"
	updated, err := c.UpdateSCIMUser(ctx, 9, 2, &name, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "Bob Smith", updated.DisplayName)
	store.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
