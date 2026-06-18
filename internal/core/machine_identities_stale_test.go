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

func TestListStaleMachineIdentities(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}))

	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()

	old := now.Add(-120 * 24 * time.Hour)
	recent := now.Add(-10 * 24 * time.Hour)
	mk := func(name, state string, created time.Time, lastSeen *time.Time) {
		require.NoError(t, db.Create(&models.MachineIdentity{
			ProjectID: 1, Name: name, IdentityType: "ci", State: state, CreatedAt: created, UpdatedAt: created, LastSeenAt: lastSeen,
		}).Error)
	}
	mk("stale-seen", MachineActive, old, &old)     // seen long ago → stale
	mk("never-old", MachineActive, old, nil)       // created long ago, never seen → stale
	mk("recent-seen", MachineActive, old, &recent) // seen recently → not stale
	mk("brand-new", MachineActive, recent, nil)    // created recently, never seen → NOT stale yet
	mk("revoked-old", MachineRevoked, old, &old)   // not active → excluded
	mk("other-project", MachineActive, old, &old)  // different project (set below)

	// Move the last one to project 2.
	require.NoError(t, db.Model(&models.MachineIdentity{}).Where("name = ?", "other-project").Update("project_id", 2).Error)

	stale, err := c.ListStaleMachineIdentities(ctx, 1, 90*24*time.Hour)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, m := range stale {
		names[m.Name] = true
	}
	assert.True(t, names["stale-seen"], "seen long ago is stale")
	assert.True(t, names["never-old"], "created long ago + never seen is stale")
	assert.False(t, names["recent-seen"], "recently seen is not stale")
	assert.False(t, names["brand-new"], "recently created + never seen is not stale yet")
	assert.False(t, names["revoked-old"], "non-active is excluded")
	assert.False(t, names["other-project"], "another project's identity is excluded")
	assert.Len(t, stale, 2)
}
