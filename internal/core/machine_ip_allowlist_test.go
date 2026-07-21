package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestIssueMachineToken_StoresCIDRs verifies that allowed_cidrs are JSON-encoded
// into the stored credential when a non-empty slice is supplied.
func TestIssueMachineToken_StoresCIDRs(t *testing.T) {
	store := new(MockStorage)
	fixed := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)

	store.On("GetMachineIdentity", mock.Anything, uint(1)).
		Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	store.On("CreateMachineIdentityCredential", mock.Anything, mock.AnythingOfType("*models.MachineIdentityCredential")).
		Return(&models.MachineIdentityCredential{ID: 7}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	cidrs := []string{"10.0.0.0/8", "192.0.2.0/24"}
	_, err := c.IssueMachineToken(context.Background(), 2, 1, "ci", nil, "", 9, cidrs)
	require.NoError(t, err)

	var stored *models.MachineIdentityCredential
	for _, call := range store.Calls {
		if call.Method == "CreateMachineIdentityCredential" {
			stored = call.Arguments.Get(1).(*models.MachineIdentityCredential)
		}
	}
	require.NotNil(t, stored)
	assert.Contains(t, stored.AllowedCIDRs, "10.0.0.0/8")
	assert.Contains(t, stored.AllowedCIDRs, "192.0.2.0/24")
}

// TestIssueMachineToken_NilCIDRsOmitted verifies that no AllowedCIDRs JSON is
// written when the caller passes nil (most existing callers).
func TestIssueMachineToken_NilCIDRsOmitted(t *testing.T) {
	store := new(MockStorage)
	fixed := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)

	store.On("GetMachineIdentity", mock.Anything, uint(1)).
		Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	store.On("CreateMachineIdentityCredential", mock.Anything, mock.AnythingOfType("*models.MachineIdentityCredential")).
		Return(&models.MachineIdentityCredential{ID: 8}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	_, err := c.IssueMachineToken(context.Background(), 2, 1, "ci", nil, "", 9, nil)
	require.NoError(t, err)

	var stored *models.MachineIdentityCredential
	for _, call := range store.Calls {
		if call.Method == "CreateMachineIdentityCredential" {
			stored = call.Arguments.Get(1).(*models.MachineIdentityCredential)
		}
	}
	require.NotNil(t, stored)
	assert.Empty(t, stored.AllowedCIDRs)
}

// TestValidateMachineToken_ReturnsCIDRRestriction verifies that a credential
// with AllowedCIDRs in JSON returns a non-nil MachineTokenRestriction.
func TestValidateMachineToken_ReturnsCIDRRestriction(t *testing.T) {
	raw := "kx_machine_cidr_test"
	hash := sha256Hex(raw)
	fixed := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)

	store := new(MockStorage)
	store.On("GetMachineIdentityCredentialByHash", mock.Anything, hash).
		Return(&models.MachineIdentityCredential{
			ID:                1,
			MachineIdentityID: 5,
			AllowedCIDRs:      `["10.0.0.0/8","192.168.1.0/24"]`,
		}, nil)
	store.On("GetMachineIdentity", mock.Anything, uint(5)).
		Return(&models.MachineIdentity{ID: 5, Name: "cidr-bot", State: MachineActive}, nil)
	store.On("GetMachineRoles", mock.Anything, uint(5)).Return([]*models.Role{{Name: "viewer"}}, nil)
	store.On("TouchMachineIdentityCredential", mock.Anything, uint(1), fixed, machineTouchInterval).Return(nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	_, _, restriction, err := c.ValidateMachineToken(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, restriction)
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.1.0/24"}, restriction.AllowedCIDRs)
}

// TestMachineRestrictionFrom covers the machineRestrictionFrom helper directly.
func TestMachineRestrictionFrom(t *testing.T) {
	t.Run("empty AllowedCIDRs returns nil", func(t *testing.T) {
		cred := &models.MachineIdentityCredential{}
		assert.Nil(t, machineRestrictionFrom(cred))
	})

	t.Run("valid JSON returns restriction", func(t *testing.T) {
		cred := &models.MachineIdentityCredential{AllowedCIDRs: `["10.0.0.0/8"]`}
		r := machineRestrictionFrom(cred)
		require.NotNil(t, r)
		assert.Equal(t, []string{"10.0.0.0/8"}, r.AllowedCIDRs)
	})

	t.Run("invalid JSON returns nil", func(t *testing.T) {
		cred := &models.MachineIdentityCredential{AllowedCIDRs: `not json`}
		assert.Nil(t, machineRestrictionFrom(cred))
	})

	t.Run("JSON empty array returns nil", func(t *testing.T) {
		cred := &models.MachineIdentityCredential{AllowedCIDRs: `[]`}
		assert.Nil(t, machineRestrictionFrom(cred))
	})
}
