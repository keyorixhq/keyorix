package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRateLimitCore(t *testing.T) (*KeyorixCore, func(time.Time)) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}))
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	setNow := func(t time.Time) { c.now = func() time.Time { return t } }
	return c, setNow
}

func TestRateLimit_BlocksAtBudgetAndExpiresWithWindow(t *testing.T) {
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()

	// Below the budget: allowed.
	for i := 0; i < LoginMaxAttempts-1; i++ {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "under budget is allowed")

	// Reaching the budget: blocked.
	c.RecordFailedLogin(ctx, "1.2.3.4")
	assert.True(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "at the budget the IP is blocked")

	// A different IP is unaffected.
	assert.False(t, c.IsLoginRateLimited(ctx, "9.9.9.9"))

	// After the window elapses, the old attempts no longer count.
	setNow(base.Add(LoginWindow + time.Minute))
	assert.False(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "attempts age out of the window")
}

func TestRateLimit_EmptyIPNeverLimited(t *testing.T) {
	c, _ := newRateLimitCore(t)
	ctx := context.Background()
	for i := 0; i < LoginMaxAttempts+5; i++ {
		c.RecordFailedLogin(ctx, "")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, ""), "an empty IP is never rate-limited")
}

func TestRateLimit_PruneRemovesAgedRows(t *testing.T) {
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()
	for i := 0; i < 5; i++ {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	// Move past the window and prune — aged rows are removed.
	setNow(base.Add(LoginWindow + time.Minute))
	removed, err := c.PruneLoginAttempts(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), removed)

	n, err := c.storage.CountRecentLoginAttempts(ctx, "1.2.3.4", time.Time{})
	require.NoError(t, err)
	assert.Zero(t, n, "table is empty after pruning aged rows")
}
