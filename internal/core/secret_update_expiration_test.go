package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// captureSecretFieldUpdate records the column set handed to UpdateSecretFields so
// the test can assert on what was actually WRITTEN, rather than on what the
// in-memory struct happened to hold.
//
// #2695 made this a sharper test than it was: the three-way distinction it
// exists to pin (clear the expiry / set a new one / leave it alone) used to be
// inferred from the persisted struct, where "leave it alone" and "write back the
// value I read" are indistinguishable. It is now explicit in the write itself —
// SetExpiration false means the column is not in the UPDATE at all.
func captureSecretFieldUpdate(store *MockStorage, existing *models.SecretNode) *storage.SecretFieldUpdate {
	saved := &storage.SecretFieldUpdate{}
	store.On("GetSecret", mock.Anything, existing.ID).Return(existing, nil)
	store.On("UpdateSecretFields", mock.Anything, existing.ID, mock.AnythingOfType("storage.SecretFieldUpdate")).
		Run(func(args mock.Arguments) { *saved = args.Get(2).(storage.SecretFieldUpdate) }).
		Return(true, nil)
	return saved
}

// ClearExpiration removes an existing expiry; a nil Expiration with no clear flag
// leaves it untouched (the distinction that was previously impossible to express).
func TestUpdateSecret_ClearExpiration(t *testing.T) {
	t.Parallel()
	// No deferred ResetForTesting here: TestMain owns this package's i18n
	// lifecycle (see sharing_integration_simple_test.go's note).
	require.NoError(t, i18n.InitializeForTesting())
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("clear removes the expiration", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureSecretFieldUpdate(store, &models.SecretNode{ID: 1, Name: "x", Expiration: &exp})
		c := NewKeyorixCore(store)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, ClearExpiration: true, UpdatedBy: "t"})
		require.NoError(t, err)
		require.True(t, saved.SetExpiration, "clearing must actually write the column")
		require.Nil(t, saved.Expiration, "expiration should be cleared")
	})

	t.Run("nil expiration without clear leaves it unchanged", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureSecretFieldUpdate(store, &models.SecretNode{ID: 1, Name: "x", Expiration: &exp})
		c := NewKeyorixCore(store)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, UpdatedBy: "t"})
		require.NoError(t, err)
		require.False(t, saved.SetExpiration,
			"expiration must not appear in the UPDATE at all — writing back the value that was read is "+
				"exactly how a concurrent change gets reverted (#2695)")
		require.Nil(t, saved.Expiration)
	})

	t.Run("setting a new expiration overrides", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureSecretFieldUpdate(store, &models.SecretNode{ID: 1, Name: "x"})
		c := NewKeyorixCore(store)
		newExp := exp.Add(24 * time.Hour)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, Expiration: &newExp, UpdatedBy: "t"})
		require.NoError(t, err)
		require.True(t, saved.SetExpiration)
		require.NotNil(t, saved.Expiration)
		require.Equal(t, newExp, *saved.Expiration)
	})
}
