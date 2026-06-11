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

func newMachineCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

func TestCanTransitionMachine(t *testing.T) {
	valid := [][2]string{
		{MachinePending, MachineActive},
		{MachineActive, MachineSuspended},
		{MachineSuspended, MachineActive},
		{MachineActive, MachineRevoked},
		{MachineSuspended, MachineRevoked},
		{MachinePending, MachineRevoked},
	}
	for _, tc := range valid {
		assert.True(t, canTransitionMachine(tc[0], tc[1]), "%s→%s allowed", tc[0], tc[1])
	}
	invalid := [][2]string{
		{MachinePending, MachineSuspended},
		{MachineRevoked, MachineActive}, // terminal
		{MachineActive, MachinePending},
	}
	for _, tc := range invalid {
		assert.False(t, canTransitionMachine(tc[0], tc[1]), "%s→%s rejected", tc[0], tc[1])
	}
}

func TestCreateMachineIdentity(t *testing.T) {
	t.Run("creates an active identity and audits", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineActive && m.IdentityType == MachineTypeCI && m.ProjectID == 1
		})).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, Name: "ci-runner", IdentityType: MachineTypeCI, State: MachineActive}, nil)
		store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
			return e.EventType == "machine_identity.created"
		})).Return(nil)

		m, err := c.CreateMachineIdentity(ctx, 1, "ci-runner", MachineTypeCI, "GitHub Actions", 9)
		require.NoError(t, err)
		assert.Equal(t, MachineActive, m.State)
		store.AssertExpectations(t)
	})

	t.Run("rejects an unknown identity type", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		_, err := c.CreateMachineIdentity(context.Background(), 1, "x", "robot", "", 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid identity_type")
		store.AssertNotCalled(t, "CreateMachineIdentity", mock.Anything, mock.Anything)
	})

	t.Run("defaults a blank type to other", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.IdentityType == MachineTypeOther
		})).Return(&models.MachineIdentity{ID: 11, IdentityType: MachineTypeOther, State: MachineActive}, nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		_, err := c.CreateMachineIdentity(ctx, 1, "x", "", "", 9)
		require.NoError(t, err)
	})
}

func TestTransitionMachineIdentity(t *testing.T) {
	t.Run("suspends an active identity", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("GetMachineIdentity", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("UpdateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		})).Return(nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		m, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.NoError(t, err)
		assert.Equal(t, MachineSuspended, m.State)
	})

	t.Run("revoke stamps revoked_at", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("GetMachineIdentity", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("UpdateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineRevoked && m.RevokedAt != nil
		})).Return(nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineRevoked, 9)
		require.NoError(t, err)
	})

	t.Run("rejects an illegal transition", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("GetMachineIdentity", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineRevoked}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineActive, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "UpdateMachineIdentity", mock.Anything, mock.Anything)
	})

	// Cross-project guard: a machine in project 2 must not be reachable when the
	// caller is authorized for project 1.
	t.Run("rejects a machine in another project", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("GetMachineIdentity", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 2, State: MachineActive}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		store.AssertNotCalled(t, "UpdateMachineIdentity", mock.Anything, mock.Anything)
	})
}
