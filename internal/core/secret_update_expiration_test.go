package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// captureUpdatedSecret records the secret handed to UpdateSecret so the test can
// assert on the persisted Expiration field.
func captureUpdatedSecret(store *MockStorage, existing *models.SecretNode) *models.SecretNode {
	saved := &models.SecretNode{}
	store.On("GetSecret", mock.Anything, existing.ID).Return(existing, nil)
	store.On("UpdateSecret", mock.Anything, mock.AnythingOfType("*models.SecretNode")).
		Run(func(args mock.Arguments) { *saved = *args.Get(1).(*models.SecretNode) }).
		Return(saved, nil)
	return saved
}

// ClearExpiration removes an existing expiry; a nil Expiration with no clear flag
// leaves it untouched (the distinction that was previously impossible to express).
func TestUpdateSecret_ClearExpiration(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("clear removes the expiration", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureUpdatedSecret(store, &models.SecretNode{ID: 1, Name: "x", Expiration: &exp})
		c := NewKeyorixCore(store)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, ClearExpiration: true, UpdatedBy: "t"})
		require.NoError(t, err)
		require.Nil(t, saved.Expiration, "expiration should be cleared")
	})

	t.Run("nil expiration without clear leaves it unchanged", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureUpdatedSecret(store, &models.SecretNode{ID: 1, Name: "x", Expiration: &exp})
		c := NewKeyorixCore(store)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, UpdatedBy: "t"})
		require.NoError(t, err)
		require.NotNil(t, saved.Expiration, "expiration should be untouched")
		require.Equal(t, exp, *saved.Expiration)
	})

	t.Run("setting a new expiration overrides", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureUpdatedSecret(store, &models.SecretNode{ID: 1, Name: "x"})
		c := NewKeyorixCore(store)
		newExp := exp.Add(24 * time.Hour)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, Expiration: &newExp, UpdatedBy: "t"})
		require.NoError(t, err)
		require.NotNil(t, saved.Expiration)
		require.Equal(t, newExp, *saved.Expiration)
	})
}
