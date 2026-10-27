package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (f *cryptoInvFixture) dekAsset(t *testing.T) cryptoinventory.Asset {
	t.Helper()
	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data cryptoinventory.Inventory `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	for _, a := range env.Data.Assets {
		if a.ID == "dek" {
			return a
		}
	}
	require.Fail(t, "dek asset missing")
	return cryptoinventory.Asset{}
}

// The DEK epoch row's updated_at is the recorded time; the key file's mtime
// (set here to a very different date) must not be used when it exists.
func TestCryptoInventoryHandler_DEKCreatedAtFromEpochRow(t *testing.T) {
	f := newCryptoInvFixture(t)
	epochAt := time.Now().UTC().Add(-200 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKEpochMetadataKey, Value: "fingerprint-abc", UpdatedAt: epochAt}).Error)
	mtime := time.Now().Add(-3 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(f.cfg.Storage.Encryption.DEKPath, mtime, mtime))

	a := f.dekAsset(t)
	require.NotNil(t, a.CreatedAt)
	assert.WithinDuration(t, epochAt, *a.CreatedAt, time.Second)
	assert.False(t, a.CreatedAtEstimated, "an epoch-recorded time is not an estimate")
	assert.Contains(t, a.Notes, "DEK epoch")
}

func TestCryptoInventoryHandler_DEKCreatedAtFallsBackToMtimeAsEstimated(t *testing.T) {
	mtime := time.Now().UTC().Add(-3 * 24 * time.Hour).Truncate(time.Second)

	for name, setup := range map[string]func(*cryptoInvFixture){
		"no epoch row (SQLite, or before the epoch was seeded)": func(*cryptoInvFixture) {},
		"rotation in flight": func(f *cryptoInvFixture) {
			require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKEpochMetadataKey,
				Value: "rotating:fingerprint-old", UpdatedAt: time.Now().Add(-time.Hour)}).Error)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCryptoInvFixture(t)
			setup(f)
			require.NoError(t, os.Chtimes(f.cfg.Storage.Encryption.DEKPath, mtime, mtime))
			a := f.dekAsset(t)
			require.NotNil(t, a.CreatedAt)
			assert.WithinDuration(t, mtime, *a.CreatedAt, time.Second)
			assert.True(t, a.CreatedAtEstimated)
			assert.Contains(t, a.Notes, "estimated")
		})
	}
}

func TestCryptoInventoryHandler_DEKWithoutAnySourceHasNoCreatedAt(t *testing.T) {
	f := newCryptoInvFixture(t)
	require.NoError(t, os.Remove(f.cfg.Storage.Encryption.DEKPath))
	a := f.dekAsset(t)
	assert.Nil(t, a.CreatedAt)
	assert.False(t, a.CreatedAtEstimated, "nothing to estimate")
}
