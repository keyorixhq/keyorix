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

		m, err := c.CreateMachineIdentity(ctx, 1, "ci-runner", MachineTypeCI, "GitHub Actions", "", 9)
		require.NoError(t, err)
		assert.Equal(t, MachineActive, m.State)
		store.AssertExpectations(t)
	})

	t.Run("rejects an unknown identity type", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		_, err := c.CreateMachineIdentity(context.Background(), 1, "x", "robot", "", "", 9)
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

		_, err := c.CreateMachineIdentity(ctx, 1, "x", "", "", "", 9)
		require.NoError(t, err)
	})
}

func TestTransitionMachineIdentity(t *testing.T) {
	t.Run("suspends an active identity", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(true, nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		m, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.NoError(t, err)
		assert.Equal(t, MachineSuspended, m.State)
	})

	t.Run("revoke stamps revoked_at", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineRevoked && m.RevokedAt != nil
		}), MachineActive).Return(true, nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineRevoked, 9)
		require.NoError(t, err)
	})

	t.Run("rejects an illegal transition", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineRevoked}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineActive, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})

	// Cross-project guard: a machine in project 2 must not be reachable when the
	// caller is authorized for project 1.
	t.Run("rejects a machine in another project", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 2, State: MachineActive}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})

	// #388: a concurrent revoke and reactivate racing off the same pre-transition
	// state must not silently un-revoke — the second transition observes the
	// FIRST one's already-committed state under the row lock and is rejected as an
	// illegal transition (revoked is terminal), not applied blindly.
	t.Run("second racing transition sees the first's committed state, not the stale one", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		// Both callers "observed" active/suspended before racing; by the time the second
		// transition's LockMachineIdentityForUpdate call runs, the first has already
		// committed revoked — WithTransaction in tests calls fn directly, so this models
		// the real DB row-lock serializing to reflect the just-committed state.
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineRevoked}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineActive, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})

	// #518: even after the row-lock read reports a legal from-state, a
	// concurrent writer (only possible under storage.type: remote, where
	// WithTransaction is a no-op and the "lock" is a plain read — see
	// TransitionMachineIdentityState's interface doc) can still win the actual
	// write race. TransitionMachineIdentityState reporting matched=false must be
	// treated exactly like an illegal transition, not silently accepted.
	t.Run("lost race on the conditional write is reported like an illegal transition", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(false, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	})
}
