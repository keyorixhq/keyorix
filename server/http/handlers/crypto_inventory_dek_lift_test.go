package handlers

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Review finding (#3754): a failed or interrupted rotation lifts its fence by
// rewriting the epoch row with the OLD DEK's fingerprint, which bumps the row's
// updated_at. A settled epoch row alone therefore never dates the DEK.
func TestCryptoInventoryHandler_DEKEpochRowAloneIsNotARecordedTime(t *testing.T) {
	f := newCryptoInvFixture(t)
	liftedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, f.db.Create(&models.SystemMetadata{Key: encryption.DEKEpochMetadataKey, Value: "fingerprint-old", UpdatedAt: liftedAt}).Error)
	mtime := time.Now().UTC().Add(-90 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, os.Chtimes(f.cfg.Storage.Encryption.DEKPath, mtime, mtime))

	a := f.dekAsset(t)
	require.NotNil(t, a.CreatedAt)
	assert.WithinDuration(t, mtime, *a.CreatedAt, time.Second, "the fence-lift time must not be reported as the DEK's creation")
	assert.True(t, a.CreatedAtEstimated)
}
