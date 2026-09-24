package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRecoveryKeyStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "recovery_key_"+t.Name(), &models.RecoveryKeyRecord{})
}

func TestRecoveryKeyRecord_GetOnEmptyInstall(t *testing.T) {
	ctx := context.Background()
	ls := newRecoveryKeyStore(t)

	rec, found, err := ls.GetRecoveryKeyRecord(ctx)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, rec)
}

func TestRecoveryKeyRecord_GenerateThenGet(t *testing.T) {
	ctx := context.Background()
	ls := newRecoveryKeyStore(t)

	require.NoError(t, ls.SetRecoveryKeyRecord(ctx, &models.RecoveryKeyRecord{
		KeyHash:    "deadbeef",
		KeyVersion: 1,
		CreatedAt:  time.Now(),
	}))

	rec, found, err := ls.GetRecoveryKeyRecord(ctx)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "deadbeef", rec.KeyHash)
	assert.Equal(t, 1, rec.KeyVersion)
	assert.Nil(t, rec.RotatedAt)
}

// TestRecoveryKeyRecord_RotationOverwritesInPlace pins design §2's "overwrites
// the stored hash and bumps key_version in one write" — SetRecoveryKeyRecord
// is a singleton upsert, not an append; a rotation must never leave the old
// row queryable through any code path this package exposes.
func TestRecoveryKeyRecord_RotationOverwritesInPlace(t *testing.T) {
	ctx := context.Background()
	ls := newRecoveryKeyStore(t)

	created := time.Now().Add(-24 * time.Hour)
	require.NoError(t, ls.SetRecoveryKeyRecord(ctx, &models.RecoveryKeyRecord{
		KeyHash:    "old-hash",
		KeyVersion: 1,
		CreatedAt:  created,
	}))

	rotatedAt := time.Now()
	require.NoError(t, ls.SetRecoveryKeyRecord(ctx, &models.RecoveryKeyRecord{
		KeyHash:    "new-hash",
		KeyVersion: 2,
		CreatedAt:  time.Now(), // deliberately NOT `created` — must be ignored on update
		RotatedAt:  &rotatedAt,
	}))

	rec, found, err := ls.GetRecoveryKeyRecord(ctx)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "new-hash", rec.KeyHash)
	assert.Equal(t, 2, rec.KeyVersion)
	require.NotNil(t, rec.RotatedAt)
	assert.WithinDuration(t, rotatedAt, *rec.RotatedAt, time.Second)

	// CreatedAt must be preserved from the ORIGINAL row — a rotation is not a
	// re-generation event for the purposes of "when was this key first
	// established," only KeyHash/KeyVersion/RotatedAt change.
	assert.WithinDuration(t, created, rec.CreatedAt, time.Second)

	// Exactly one row — the "singleton" contract in the doc comment, not just
	// "the get call happens to return the newest one."
	var count int64
	require.NoError(t, ls.db.Model(&models.RecoveryKeyRecord{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}
