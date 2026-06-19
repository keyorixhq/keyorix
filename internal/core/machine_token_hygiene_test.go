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

func TestListMachineTokenHygiene(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentityCredential{}))

	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()

	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	ahead := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	day := 24 * time.Hour

	mk := func(id uint, name string, created time.Time, lastUsed, expires *time.Time, revoked bool) {
		require.NoError(t, db.Create(&models.MachineIdentityCredential{
			ID: id, MachineIdentityID: 5, Name: name, TokenHash: name + "-h", TokenPrefix: "kx_machine_" + name,
			CreatedAt: created, LastUsedAt: lastUsed, ExpiresAt: expires, Revoked: revoked,
		}).Error)
	}

	mk(1, "healthy", now.Add(-10*day), ago(1*day), ahead(30*day), false)  // recent + not expired
	mk(2, "stale", now.Add(-200*day), ago(120*day), ahead(30*day), false) // unused 120d → stale
	mk(3, "never-old", now.Add(-120*day), nil, nil, false)                // never used, old → stale
	mk(4, "never-new", now.Add(-5*day), nil, nil, false)                  // never used, new → healthy
	mk(5, "expired", now.Add(-10*day), ago(1*day), ago(2*day), false)     // expired, recent use → expired only
	mk(6, "revoked-stale", now.Add(-200*day), ago(150*day), nil, true)    // stale but revoked → excluded

	t.Run("flags stale + expired-but-active, excludes healthy/fresh/revoked", func(t *testing.T) {
		entries, err := c.ListMachineTokenHygiene(ctx, 90*day)
		require.NoError(t, err)
		byName := map[string]MachineTokenHygieneEntry{}
		for _, e := range entries {
			byName[e.Credential.Name] = e
		}
		require.Len(t, entries, 3)
		assert.True(t, byName["stale"].Stale && !byName["stale"].Expired)
		assert.True(t, byName["never-old"].Stale)
		assert.True(t, byName["expired"].Expired && !byName["expired"].Stale)
		_, healthy := byName["healthy"]
		_, fresh := byName["never-new"]
		_, revoked := byName["revoked-stale"]
		assert.False(t, healthy)
		assert.False(t, fresh)
		assert.False(t, revoked, "revoked excluded at the storage layer")
	})

	t.Run("non-positive window falls back to the default", func(t *testing.T) {
		entries, err := c.ListMachineTokenHygiene(ctx, 0)
		require.NoError(t, err)
		assert.Len(t, entries, 3)
	})
}
