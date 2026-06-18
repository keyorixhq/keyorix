package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestListPATHygiene(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}))

	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()

	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	ahead := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	day := 24 * time.Hour

	mk := func(id uint, name string, created time.Time, lastUsed, expires *time.Time, revoked bool) {
		require.NoError(t, db.Create(&models.PersonalAccessToken{
			ID: id, UserID: 7, Name: name, TokenHash: name + "-hash", TokenPrefix: "kx_pat_" + name,
			CreatedAt: created, LastUsedAt: lastUsed, ExpiresAt: expires, Revoked: revoked,
		}).Error)
	}

	mk(1, "healthy", now.Add(-10*day), ago(1*day), ahead(30*day), false)  // recent use, not expired
	mk(2, "stale", now.Add(-200*day), ago(120*day), ahead(30*day), false) // unused 120d → stale
	mk(3, "never-old", now.Add(-120*day), nil, nil, false)                // never used, created 120d ago → stale
	mk(4, "never-new", now.Add(-5*day), nil, nil, false)                  // never used, created 5d ago → healthy
	mk(5, "expired", now.Add(-10*day), ago(1*day), ago(2*day), false)     // expired but recently used → expired only
	mk(6, "revoked-stale", now.Add(-200*day), ago(150*day), nil, true)    // stale but revoked → excluded

	t.Run("flags stale and expired-but-active, excludes healthy and revoked", func(t *testing.T) {
		entries, err := c.ListPATHygiene(ctx, 90*day)
		require.NoError(t, err)
		byName := map[string]PATHygieneEntry{}
		for _, e := range entries {
			byName[e.Token.Name] = e
		}
		require.Len(t, entries, 3, "stale + never-old + expired")
		assert.True(t, byName["stale"].Stale)
		assert.False(t, byName["stale"].Expired)
		assert.True(t, byName["never-old"].Stale)
		assert.True(t, byName["expired"].Expired)
		assert.False(t, byName["expired"].Stale, "used yesterday — not stale")
		_, healthy := byName["healthy"]
		assert.False(t, healthy)
		_, fresh := byName["never-new"]
		assert.False(t, fresh)
		_, revoked := byName["revoked-stale"]
		assert.False(t, revoked, "revoked tokens are excluded at the storage layer")
	})

	t.Run("a shorter window flags more tokens", func(t *testing.T) {
		// Under a 4-day window, the never-used token created 5 days ago also goes stale.
		entries, err := c.ListPATHygiene(ctx, 4*day)
		require.NoError(t, err)
		names := map[string]bool{}
		for _, e := range entries {
			names[e.Token.Name] = true
		}
		assert.True(t, names["never-new"], "created 5d ago, never used → stale under a 4d window")
		assert.False(t, names["healthy"], "used 1d ago → still not stale under a 4d window")
	})

	t.Run("a non-positive window falls back to the default", func(t *testing.T) {
		entries, err := c.ListPATHygiene(ctx, 0)
		require.NoError(t, err)
		// 90-day default: same three as the explicit 90-day call.
		assert.Len(t, entries, 3)
	})
}
