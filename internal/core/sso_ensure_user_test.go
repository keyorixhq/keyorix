// sso_ensure_user_test.go covers ensureSSOUser's three branches (sso.go) --
// every existing CompleteSSO test resolves an EXISTING user via
// GetUserByExternalID, so only the "existing != nil" branch had ever run.
// Untested before this file: auto-provisioning disabled (a clean rejection,
// not a silent account creation) and auto-provisioning enabled (the full JIT
// account-creation path, provisionSSOUser).
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEnsureSSOUser_ExistingReturnedDirectly(t *testing.T) {
	c, _, _, p := ssoTestCore(t)
	existing := &models.User{ID: 7, Email: "ada@x.io"}
	got, err := c.ensureSSOUser(context.Background(), p, existing, "okta|7", "ada@x.io", true, "Ada")
	require.NoError(t, err)
	assert.Same(t, existing, got)
}

func TestEnsureSSOUser_NoAutoProvision_Rejected(t *testing.T) {
	c, _, _, p := ssoTestCore(t)
	p.AutoProvision = false
	_, err := c.ensureSSOUser(context.Background(), p, nil, "okta|new", "new@x.io", true, "New Person")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Keyorix account matches")
}

// TestEnsureSSOUser_AutoProvision_CreatesUser exercises the full JIT
// provisioning path (provisionSSOUser): no existing user by external ID or
// email, a fresh username derived, the account created active with the
// provider's default role assigned.
func TestEnsureSSOUser_AutoProvision_CreatesUser(t *testing.T) {
	c, store, _, p := ssoTestCore(t)
	p.AutoProvision = true
	p.DefaultRole = "system_viewer"

	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|new").
		Return(nil, storage.ErrUserNotFound).Once() // provisionSSOUser's own race-guard call to resolveSSOUser
	store.On("GetUserByEmail", mock.Anything, "new@x.io").
		Return(nil, storage.ErrUserNotFound).Once()
	store.On("GetUserByUsername", mock.Anything, "new").
		Return(nil, storage.ErrUserNotFound)
	store.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).
		Return(&models.User{ID: 42, Username: "new", Email: "new@x.io", ExternalID: "sso:okta:okta|new"}, nil)
	store.On("GetRoleByName", mock.Anything, "system_viewer").
		Return(&models.Role{ID: 3, Name: "system_viewer"}, nil)
	store.On("AssignRole", mock.Anything, uint(42), uint(3), storage.Scope{}).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	got, err := c.ensureSSOUser(context.Background(), p, nil, "okta|new", "new@x.io", true, "New Person")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint(42), got.ID)
	store.AssertCalled(t, "AssignRole", mock.Anything, uint(42), uint(3), storage.Scope{})
}

// TestEnsureSSOUser_AutoProvision_NoEmail_Rejected pins provisionSSOUser's own
// precondition: an IdP assertion with no email can never be auto-provisioned,
// regardless of AutoProvision being enabled.
func TestEnsureSSOUser_AutoProvision_NoEmail_Rejected(t *testing.T) {
	c, _, _, p := ssoTestCore(t)
	p.AutoProvision = true
	_, err := c.ensureSSOUser(context.Background(), p, nil, "okta|new", "", true, "New Person")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no email")
}
