package coretests

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ERRSTRING-CLASS-1 item 3: only the typed storage.ErrRotationPolicyNotFound means "no
// policy covers this secret". A storage fault whose text merely contains "not found"
// (a replica error, a driver message) used to read as "idle", hiding a failing
// rotation behind a healthy-looking state.

func TestGetRotationState_UntypedNotFoundTextIsAnError(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)
	store.On("GetRotationPolicyBySecret", mock.Anything, uint(7)).
		Return(nil, errors.New("replica: relation lookup failed, tuple not found in cache"))

	info, err := c.GetRotationState(context.Background(), 7)
	require.Error(t, err)
	assert.Nil(t, info)
}

func TestGetRotationState_TypedNotFoundIsIdle(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)
	store.On("GetRotationPolicyBySecret", mock.Anything, uint(7)).
		Return(nil, storage.NotFound(storage.ErrRotationPolicyNotFound, storage.ErrRotationPolicyNotFound.Error(), errors.New("record not found")))

	info, err := c.GetRotationState(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, core.RotationStateIdle, info.State)
	assert.Nil(t, info.PolicyID)
}

func TestSetRotationState_UntypedNotFoundTextKeepsTheStorageError(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)
	cause := errors.New("replica: tuple not found in cache")
	store.On("UpdateRotationState", mock.Anything, uint(99), core.RotationStateIdle, "").Return(cause)

	err := c.SetRotationState(context.Background(), 99, core.RotationStateIdle, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, cause, "a storage fault is wrapped, not rewritten into 'policy not found'")
	assert.NotErrorIs(t, err, storage.ErrRotationPolicyNotFound)
}

func TestSetRotationState_TypedNotFoundSaysPolicyNotFound(t *testing.T) {
	t.Parallel()
	store := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(store)
	store.On("UpdateRotationState", mock.Anything, uint(99), core.RotationStateIdle, "").
		Return(storage.NotFound(storage.ErrRotationPolicyNotFound, storage.ErrRotationPolicyNotFound.Error(), errors.New("record not found")))

	err := c.SetRotationState(context.Background(), 99, core.RotationStateIdle, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation policy 99 not found")
}
