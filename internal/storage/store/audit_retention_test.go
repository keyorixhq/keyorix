package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAuditRetentionTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewLocalStorage(db)
}

func TestAuditRetentionStats_Empty(t *testing.T) {
	ls := newAuditRetentionTestStore(t)

	stats, err := ls.AuditRetentionStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.TotalEvents)
	assert.Nil(t, stats.Oldest, "no oldest on an empty table")
	assert.Nil(t, stats.Newest, "no newest on an empty table")
}

func TestAuditRetentionStats_OldestNewestAndCount(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	oldest := now.AddDate(0, 0, -400) // > 12 months back
	mid := now.AddDate(0, 0, -30)
	newest := now.AddDate(0, 0, -1)

	for _, at := range []time.Time{mid, oldest, newest} {
		require.NoError(t, ls.db.WithContext(ctx).Create(&models.AuditEvent{
			EventType: "secret.read", EventTime: at,
		}).Error)
	}

	stats, err := ls.AuditRetentionStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalEvents)
	require.NotNil(t, stats.Oldest)
	require.NotNil(t, stats.Newest)
	assert.WithinDuration(t, oldest, *stats.Oldest, time.Second)
	assert.WithinDuration(t, newest, *stats.Newest, time.Second)
}
