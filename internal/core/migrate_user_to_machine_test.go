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

func TestMigrateUserToMachine(t *testing.T) {
	t.Run("creates a service identity, suspends the source user, and audits", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()

		store.On("GetUserByUsername", ctx, "ci-bot").
			Return(&models.User{ID: 7, Username: "ci-bot", Email: "ci-bot@example.com", AccountState: "active"}, nil)
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.ProjectID == 3 && m.Name == "ci-bot" && m.IdentityType == MachineTypeService && m.State == MachineActive
		})).Return(&models.MachineIdentity{ID: 20, ProjectID: 3, Name: "ci-bot", IdentityType: MachineTypeService, State: MachineActive}, nil)
		// SuspendUser path: guardLastAdminDeactivation (#G02) → LockUserForUpdate →
		// SetAccountState(account_state=suspended) → purge the migrated user's
		// sessions (suspension revokes existing tokens). The migrated user holds
		// no roles in this fixture, so the guard is a no-op.
		store.On("GetUserRoleIDsAt", ctx, uint(7), Scope{}).Return([]uint{}, nil)
		store.On("GetUserGroupRoleIDsAt", ctx, uint(7), Scope{}).Return([]uint{}, nil)
		store.On("GetUser", ctx, uint(7)).
			Return(&models.User{ID: 7, Username: "ci-bot", AccountState: "active"}, nil)
		store.On("SetAccountState", ctx, uint(7), AccountSuspended, mock.Anything).Return(nil)
		store.On("DeleteSessionsForUserExcept", ctx, uint(7), uint(0)).Return(nil)
		// Suspension also evicts the user's cached session tokens and revokes their PATs.
		store.On("ListSessionTokenHashesForUser", ctx, uint(7)).Return([]string{}, nil)
		// H-2: ALL state transitions collect PAT hashes for cache eviction.
		store.On("ListPersonalAccessTokensByUser", ctx, uint(7)).Return([]*models.PersonalAccessToken{}, nil)
		store.On("RevokeAllPersonalAccessTokensForUser", ctx, uint(7)).Return([]string{}, nil)

		seen := map[string]bool{}
		store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
			seen[e.EventType] = true
			return true
		})).Return(nil)

		m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 9, true)
		require.NoError(t, err)
		assert.Equal(t, uint(20), m.ID)
		assert.Equal(t, MachineTypeService, m.IdentityType)
		assert.True(t, seen["machine_identity.created"], "create event")
		assert.True(t, seen["account.suspended"], "suspend event")
		assert.True(t, seen["machine_identity.migrated_from_user"], "migration event")
		store.AssertExpectations(t)
	})

	t.Run("keep-user leaves the source account untouched", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()

		store.On("GetUserByUsername", ctx, "svc").
			Return(&models.User{ID: 5, Username: "svc", Email: "svc@example.com"}, nil)
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.Name == "renamed" && m.IdentityType == MachineTypeAutomation
		})).Return(&models.MachineIdentity{ID: 21, Name: "renamed", IdentityType: MachineTypeAutomation, State: MachineActive}, nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		_, err := c.MigrateUserToMachine(ctx, "svc", 1, MachineTypeAutomation, "renamed", 9, false)
		require.NoError(t, err)
		store.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		store.AssertExpectations(t)
	})

	t.Run("rejects an unknown user without creating anything", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("GetUserByUsername", ctx, "ghost").Return((*models.User)(nil), errors.New("not found"))

		_, err := c.MigrateUserToMachine(ctx, "ghost", 1, "", "", 9, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ghost")
		store.AssertNotCalled(t, "CreateMachineIdentity", mock.Anything, mock.Anything)
	})

	t.Run("validates required inputs", func(t *testing.T) {
		c := newMachineCore(new(MockStorage))
		_, err := c.MigrateUserToMachine(context.Background(), "", 1, "", "", 9, true)
		require.Error(t, err)
		_, err = c.MigrateUserToMachine(context.Background(), "x", 0, "", "", 9, true)
		require.Error(t, err)
	})
}
