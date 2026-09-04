package store

// secret_size_cap_storage_test.go proves the storage-layer defence-in-depth
// backstop (maxSecretVersionValueSize, local_secrets.go) fires on its own --
// i.e. even when called directly, bypassing every transport and core-layer
// check above it.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestLocalStorage_CreateSecretVersion_SecretSizeCap(t *testing.T) {
	ls := newMaxStore(t, "secret_size_cap", &models.SecretNode{}, &models.SecretVersion{})
	ctx := context.Background()

	t.Run("exactly at the hard ceiling is accepted", func(t *testing.T) {
		v := &models.SecretVersion{
			SecretNodeID: 1, VersionNumber: 1,
			EncryptedValue: make([]byte, maxSecretVersionValueSize),
		}
		created, err := ls.CreateSecretVersion(ctx, v)
		require.NoError(t, err)
		require.NotNil(t, created)
	})

	t.Run("one byte over the hard ceiling is rejected, bypassing every transport/core check", func(t *testing.T) {
		v := &models.SecretVersion{
			SecretNodeID: 1, VersionNumber: 2,
			EncryptedValue: make([]byte, maxSecretVersionValueSize+1),
		}
		created, err := ls.CreateSecretVersion(ctx, v)
		require.Error(t, err)
		require.Nil(t, created)
		require.True(t, errors.Is(err, storage.ErrSecretValueTooLarge),
			"error must wrap storage.ErrSecretValueTooLarge, got: %v", err)
	})
}
