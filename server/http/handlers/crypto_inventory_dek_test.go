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

// The dek.created_at row is the recorded time when it names the epoch's DEK; the
// key file's mtime (set here to a very different date) and the epoch row's own
// updated_at (rewritten by a fence lift) must not be used.
func TestCryptoInventoryHandler_DEKCreatedAtFromRecordedRow(t *testing.T) {
	f := newCryptoInvFixture(t)
	createdAt := time.Now().UTC().Add(-200 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKEpochMetadataKey, Value: "fingerprint-abc", UpdatedAt: time.Now().UTC()}).Error)
	require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKCreatedAtMetadataKey,
		Value: "fingerprint-abc " + createdAt.Format(time.RFC3339Nano), UpdatedAt: createdAt}).Error)
	mtime := time.Now().Add(-3 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(f.cfg.Storage.Encryption.DEKPath, mtime, mtime))

	a := f.dekAsset(t)
	require.NotNil(t, a.CreatedAt)
	assert.WithinDuration(t, createdAt, *a.CreatedAt, time.Second)
	assert.False(t, a.CreatedAtEstimated, "a recorded time is not an estimate")
	assert.Contains(t, a.Notes, "recorded in the database")
}

func TestCryptoInventoryHandler_DEKCreatedAtFallsBackToMtimeAsEstimated(t *testing.T) {
	mtime := time.Now().UTC().Add(-3 * 24 * time.Hour).Truncate(time.Second)

	for name, setup := range map[string]func(*cryptoInvFixture){
		"no epoch row (SQLite, or before the epoch was seeded)": func(*cryptoInvFixture) {},
		"rotation in flight": func(f *cryptoInvFixture) {
			require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKEpochMetadataKey,
				Value: "rotating:fingerprint-old", UpdatedAt: time.Now().Add(-time.Hour)}).Error)
			recordCreatedAt(t, f, "fingerprint-old")
		},
		"recorded row names another DEK": func(f *cryptoInvFixture) {
			require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKEpochMetadataKey,
				Value: "fingerprint-new", UpdatedAt: time.Now().Add(-time.Hour)}).Error)
			recordCreatedAt(t, f, "fingerprint-old")
		},
		"recorded row without an epoch": func(f *cryptoInvFixture) {
			recordCreatedAt(t, f, "fingerprint-old")
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

func recordCreatedAt(t *testing.T, f *cryptoInvFixture, fingerprint string) {
	t.Helper()
	at := time.Now().UTC().Add(-400 * 24 * time.Hour)
	require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKCreatedAtMetadataKey,
		Value: fingerprint + " " + at.Format(time.RFC3339Nano), UpdatedAt: at}).Error)
}
