package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newStepupStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MFAStepupToken{}))
	return NewLocalStorage(db)
}

func TestUpsertMFAStepupToken_InsertsNewRow(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 1, exp))

	var tok models.MFAStepupToken
	require.NoError(t, s.db.First(&tok).Error)
	assert.Equal(t, uint(1), tok.UserID)
	assert.WithinDuration(t, exp, tok.ExpiresAt, time.Second)
}

func TestUpsertMFAStepupToken_UpdatesExistingRow(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	first := time.Now().Add(2 * time.Minute)
	second := time.Now().Add(10 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 2, first))
	require.NoError(t, s.UpsertMFAStepupToken(ctx, 2, second))

	var count int64
	s.db.Model(&models.MFAStepupToken{}).Count(&count)
	assert.Equal(t, int64(1), count, "upsert must not create a second row")

	var tok models.MFAStepupToken
	require.NoError(t, s.db.First(&tok).Error)
	assert.WithinDuration(t, second, tok.ExpiresAt, time.Second)
}

func TestHasActiveMFAStepup_TrueWhenNotExpired(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 3, exp))

	ok, err := s.HasActiveMFAStepup(ctx, 3)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestHasActiveMFAStepup_FalseWhenExpired(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	exp := time.Now().Add(-1 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 4, exp))

	ok, err := s.HasActiveMFAStepup(ctx, 4)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestHasActiveMFAStepup_FalseWhenNoRecord(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()

	ok, err := s.HasActiveMFAStepup(ctx, 99)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestUpsertMFAStepupToken_NonUTCExpiryStoredAsUTC pins G81: MFAStepupToken
// previously had no UTC-normalizing BeforeSave hook (unlike its sibling
// MFAStepUpGrant), and its upsert's ON CONFLICT DoUpdates path bypasses model
// hooks entirely even once one exists — so an expiry constructed in a
// non-UTC local timezone (e.g. a server running with TZ set) could be
// persisted as-is. SQLite compares time.Time values as strings, so a mixed
// UTC/local ExpiresAt breaks comparisons. Sets the expiry in a fixed
// non-UTC zone and asserts the persisted value round-trips as UTC — both via
// a fresh INSERT and via the ON CONFLICT UPDATE branch (a second upsert for
// the same user), since the two branches take genuinely different code
// paths in UpsertMFAStepupToken.
func TestUpsertMFAStepupToken_NonUTCExpiryStoredAsUTC(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC-7", -7*60*60)
	exp := time.Date(2026, 8, 20, 12, 0, 0, 0, nonUTC)

	// INSERT branch.
	require.NoError(t, s.UpsertMFAStepupToken(ctx, 5, exp))
	var tok models.MFAStepupToken
	require.NoError(t, s.db.Where("user_id = ?", 5).First(&tok).Error)
	assert.Equal(t, time.UTC, tok.ExpiresAt.Location(), "expires_at must be stored in UTC after INSERT")
	assert.True(t, tok.ExpiresAt.Equal(exp), "the instant must be preserved even though the zone changed")

	// ON CONFLICT UPDATE branch — a second upsert for the same user.
	exp2 := time.Date(2026, 8, 20, 13, 0, 0, 0, nonUTC)
	require.NoError(t, s.UpsertMFAStepupToken(ctx, 5, exp2))
	require.NoError(t, s.db.Where("user_id = ?", 5).First(&tok).Error)
	assert.Equal(t, time.UTC, tok.ExpiresAt.Location(), "expires_at must be stored in UTC after the ON CONFLICT UPDATE branch")
	assert.True(t, tok.ExpiresAt.Equal(exp2))
}

// TestHasActiveMFAStepup_RecognizesNonUTCExpiryAsExpired is the detection_idea
// for G81's MFAStepupToken member directly: set an expiry in a non-UTC local
// time that has genuinely already passed, persist it, and confirm the read
// path still recognises it as expired — the exact scenario a mixed UTC/local
// ExpiresAt could silently break (SQLite's string comparison misjudging an
// expired local-time value as still-active, or vice versa, depending on the
// sign of the zone offset).
func TestHasActiveMFAStepup_RecognizesNonUTCExpiryAsExpired(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC+9", 9*60*60)
	pastExpiry := time.Now().In(nonUTC).Add(-1 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 6, pastExpiry))

	ok, err := s.HasActiveMFAStepup(ctx, 6)
	require.NoError(t, err)
	assert.False(t, ok, "a non-UTC expiry that has genuinely passed must still be recognized as expired")
}
