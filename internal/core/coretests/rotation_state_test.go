package coretests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestGetRotationState_PolicyExists verifies that a secret covered by an active
// rotation policy returns the policy's stamped state fields.
func TestGetRotationState_PolicyExists(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	policyID := uint(5)
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	policy := &models.RotationPolicy{
		ID:                policyID,
		RotationState:     core.RotationStateSucceeded,
		LastRotationError: "",
		LastStateAt:       &at,
	}
	store.On("GetRotationPolicyBySecret", mock.Anything, uint(42)).Return(policy, nil)

	info, err := c.GetRotationState(context.Background(), 42)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, uint(42), info.SecretID)
	require.NotNil(t, info.PolicyID)
	assert.Equal(t, policyID, *info.PolicyID)
	assert.Equal(t, core.RotationStateSucceeded, info.State)
	assert.Empty(t, info.LastRotationError)
	require.NotNil(t, info.LastStateAt)
	assert.Equal(t, at, *info.LastStateAt)

	store.AssertExpectations(t)
}

// TestGetRotationState_NoPolicy verifies that when no active policy covers the
// secret the response has State="idle" and PolicyID=nil (not an error).
func TestGetRotationState_NoPolicy(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	store.On("GetRotationPolicyBySecret", mock.Anything, uint(7)).
		Return(nil, storage.NotFound(storage.ErrRotationPolicyNotFound, storage.ErrRotationPolicyNotFound.Error(), errors.New("record not found")))

	info, err := c.GetRotationState(context.Background(), 7)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, uint(7), info.SecretID)
	assert.Nil(t, info.PolicyID)
	assert.Equal(t, core.RotationStateIdle, info.State)

	store.AssertExpectations(t)
}

// TestGetRotationState_EmptyStateDefaultsToIdle verifies that a policy row whose
// RotationState is "" (not yet stamped) is reported as "idle".
func TestGetRotationState_EmptyStateDefaultsToIdle(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	policyID := uint(3)
	policy := &models.RotationPolicy{
		ID:            policyID,
		RotationState: "", // never stamped yet
	}
	store.On("GetRotationPolicyBySecret", mock.Anything, uint(99)).Return(policy, nil)

	info, err := c.GetRotationState(context.Background(), 99)
	require.NoError(t, err)
	assert.Equal(t, core.RotationStateIdle, info.State)

	store.AssertExpectations(t)
}

// TestGetRotationState_StorageError verifies that a genuine storage failure is
// propagated as an error (not silenced as "no policy").
func TestGetRotationState_StorageError(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	store.On("GetRotationPolicyBySecret", mock.Anything, uint(1)).
		Return(nil, errors.New("connection refused"))

	_, err := c.GetRotationState(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	store.AssertExpectations(t)
}

// TestSetRotationState_Valid verifies that a valid state transition calls
// UpdateRotationState with the correct arguments.
func TestSetRotationState_Valid(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	store.On("UpdateRotationState", mock.Anything, uint(10), core.RotationStateFailed, "timeout").Return(nil)

	err := c.SetRotationState(context.Background(), 10, core.RotationStateFailed, "timeout")
	require.NoError(t, err)

	store.AssertExpectations(t)
}

// TestSetRotationState_InvalidState verifies that an unknown state string returns
// a validation error without calling storage.
func TestSetRotationState_InvalidState(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	err := c.SetRotationState(context.Background(), 10, "broken", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rotation state")
	// storage must NOT have been called
	store.AssertNotCalled(t, "UpdateRotationState")
}

// TestSetRotationState_NotFound verifies that "rotation policy not found" from
// storage surfaces as an error.
func TestSetRotationState_NotFound(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	store.On("UpdateRotationState", mock.Anything, uint(99), core.RotationStateIdle, "").
		Return(storage.NotFound(storage.ErrRotationPolicyNotFound, storage.ErrRotationPolicyNotFound.Error(), errors.New("record not found")))

	err := c.SetRotationState(context.Background(), 99, core.RotationStateIdle, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	store.AssertExpectations(t)
}

// TestSetRotationState_StorageError verifies that a storage failure is propagated.
func TestSetRotationState_StorageError(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)

	store.On("UpdateRotationState", mock.Anything, uint(5), core.RotationStateRotating, "").
		Return(errors.New("disk full"))

	err := c.SetRotationState(context.Background(), 5, core.RotationStateRotating, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")

	store.AssertExpectations(t)
}

// TestSetRotationState_AllValidStates verifies every valid state value is accepted.
func TestSetRotationState_AllValidStates(t *testing.T) {
	t.Parallel()
	valid := []string{
		core.RotationStateIdle,
		core.RotationStatePending,
		core.RotationStateRotating,
		core.RotationStateSucceeded,
		core.RotationStateFailed,
	}
	for _, state := range valid {
		store := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(store)
		store.On("UpdateRotationState", mock.Anything, uint(1), state, "").Return(nil)
		err := c.SetRotationState(context.Background(), 1, state, "")
		require.NoError(t, err, "state %q should be valid", state)
		store.AssertExpectations(t)
	}
}
