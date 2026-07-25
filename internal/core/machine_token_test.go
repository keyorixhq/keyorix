package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestIssueMachineToken_ActiveOnly(t *testing.T) {
	store := new(MockStorage)
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	// Suspended machine → refused.
	store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineSuspended}, nil).Once()
	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }
	_, err := c.IssueMachineToken(context.Background(), 2, 1, 7, IssueMachineTokenParams{Name: "ci"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be active")

	// Wrong project → not found (cross-project IDOR guard).
	store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	_, err = c.IssueMachineToken(context.Background(), 999, 1, 7, IssueMachineTokenParams{Name: "ci"})
	require.ErrorContains(t, err, "not found")

	// Active machine → token minted with the kx_machine_ prefix, hash stored.
	store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	store.On("CreateMachineIdentityCredential", mock.Anything, mock.AnythingOfType("*models.MachineIdentityCredential")).
		Return(&models.MachineIdentityCredential{ID: 5}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	res, err := c.IssueMachineToken(context.Background(), 2, 1, 7, IssueMachineTokenParams{Name: "ci"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.PlainToken, "kx_machine_"))

	// The stored credential carries only the hash, never the raw token.
	var created *models.MachineIdentityCredential
	for _, call := range store.Calls {
		if call.Method == "CreateMachineIdentityCredential" {
			created = call.Arguments.Get(1).(*models.MachineIdentityCredential)
		}
	}
	require.NotNil(t, created)
	require.NotEmpty(t, created.TokenHash)
	require.NotEqual(t, res.PlainToken, created.TokenHash)
	require.Equal(t, sha256Hex(res.PlainToken), created.TokenHash)
}

// RevokeMachineToken must return the revoked credential's hash so the HTTP handler can
// evict it from the auth cache immediately (otherwise it keeps authenticating ≤30s).
func TestRevokeMachineToken_ReturnsHashForCacheEviction(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	store.On("GetMachineIdentityCredentialByID", mock.Anything, uint(5)).
		Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 1, TokenHash: "hash-5"}, nil)
	store.On("RevokeMachineIdentityCredential", mock.Anything, uint(5)).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	hash, err := c.RevokeMachineToken(context.Background(), 2, 1, 5, 9)
	require.NoError(t, err)
	require.Equal(t, "hash-5", hash)
}

func TestValidateMachineToken(t *testing.T) {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	raw := "kx_machine_abc"
	hash := sha256Hex(raw)

	t.Run("valid active machine resolves roles", func(t *testing.T) {
		store := new(MockStorage)
		store.On("GetMachineIdentityCredentialByHash", mock.Anything, hash).Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 1}, nil)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, Name: "ci", State: MachineActive}, nil)
		store.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{Name: "project_viewer"}}, nil)
		c := NewKeyorixCore(store)
		c.now = func() time.Time { return fixed }

		m, roles, restriction, err := c.ValidateMachineToken(context.Background(), raw)
		require.NoError(t, err)
		require.Equal(t, uint(1), m.ID)
		require.Equal(t, []string{"project_viewer"}, roles)
		require.Nil(t, restriction)
	})

	t.Run("revoked credential rejected", func(t *testing.T) {
		store := new(MockStorage)
		store.On("GetMachineIdentityCredentialByHash", mock.Anything, hash).Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 1, Revoked: true}, nil)
		c := NewKeyorixCore(store)
		c.now = func() time.Time { return fixed }
		_, _, _, err := c.ValidateMachineToken(context.Background(), raw)
		require.ErrorContains(t, err, "revoked")
	})

	t.Run("expired credential rejected", func(t *testing.T) {
		past := fixed.Add(-time.Hour)
		store := new(MockStorage)
		store.On("GetMachineIdentityCredentialByHash", mock.Anything, hash).Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 1, ExpiresAt: &past}, nil)
		c := NewKeyorixCore(store)
		c.now = func() time.Time { return fixed }
		_, _, _, err := c.ValidateMachineToken(context.Background(), raw)
		require.ErrorContains(t, err, "expired")
	})

	t.Run("suspended machine disables its tokens", func(t *testing.T) {
		store := new(MockStorage)
		store.On("GetMachineIdentityCredentialByHash", mock.Anything, hash).Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 1}, nil)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, State: MachineSuspended}, nil)
		c := NewKeyorixCore(store)
		c.now = func() time.Time { return fixed }
		_, _, _, err := c.ValidateMachineToken(context.Background(), raw)
		require.ErrorContains(t, err, "suspended")
	})
}

func TestAuthorizePrincipal_Machine(t *testing.T) {
	scope := Scope{ProjectID: 2}

	t.Run("granted role permits", func(t *testing.T) {
		store := new(MockStorage)
		store.On("GetMachineRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{7}, nil)
		store.On("RoleSetHasPermission", mock.Anything, []uint{7}, "secrets.read").Return(true, nil)
		c := NewKeyorixCore(store)
		ok, err := c.AuthorizePrincipal(context.Background(), ActorTypeMachine, 1, "secrets.read", scope)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("no grant denies", func(t *testing.T) {
		store := new(MockStorage)
		store.On("GetMachineRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{}, nil)
		c := NewKeyorixCore(store)
		ok, err := c.AuthorizePrincipal(context.Background(), ActorTypeMachine, 1, "secrets.read", scope)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("no admin bypass for machines", func(t *testing.T) {
		// Even if a machine somehow holds an admin-named role, AuthorizePrincipal
		// goes straight to the permission check (never the admin short-circuit),
		// so a permission the role lacks is denied.
		store := new(MockStorage)
		store.On("GetMachineRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{99}, nil)
		store.On("RoleSetHasPermission", mock.Anything, []uint{99}, "users.write").Return(false, nil)
		c := NewKeyorixCore(store)
		ok, err := c.AuthorizePrincipal(context.Background(), ActorTypeMachine, 1, "users.write", scope)
		require.NoError(t, err)
		require.False(t, ok, "machines never get the admin-role bypass")
	})
}
