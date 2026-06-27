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

func TestRevokeUserSessions(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "target", Email: "t@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "bystander", Email: "b@t.com"}).Error)

	mkSession := func(id, userID uint, token string) {
		require.NoError(t, db.Create(&models.Session{ID: id, UserID: userID, SessionToken: token, CreatedAt: time.Now()}).Error)
	}
	mkSession(10, 2, "t-a") // target's
	mkSession(11, 2, "t-b") // target's
	mkSession(12, 3, "b-a") // bystander's — must survive

	// Capture auth-cache evictions so we can prove the revoked sessions are evicted (so a
	// compromised token can't keep authenticating on the cache fast path for the TTL).
	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	t.Run("revokes all of the target's sessions, leaves others", func(t *testing.T) {
		n, err := c.RevokeUserSessions(ctx, 1, 2)
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		left, err := c.storage.ListSessionsByUser(ctx, 2)
		require.NoError(t, err)
		assert.Empty(t, left, "target has no sessions left")

		other, err := c.storage.ListSessionsByUser(ctx, 3)
		require.NoError(t, err)
		assert.Len(t, other, 1, "bystander's session untouched")

		// Both of the target's session hashes were evicted from the auth cache;
		// the bystander's was not.
		assert.ElementsMatch(t, []string{"t-a", "t-b"}, evicted)
		assert.NotContains(t, evicted, "b-a")
	})

	t.Run("the account state is unchanged (force-logout, not suspend)", func(t *testing.T) {
		u, err := c.storage.GetUser(ctx, 2)
		require.NoError(t, err)
		assert.NotEqual(t, AccountSuspended, u.AccountState)
	})

	t.Run("a second run revokes nothing", func(t *testing.T) {
		n, err := c.RevokeUserSessions(ctx, 1, 2)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("an audit event is recorded", func(t *testing.T) {
		var count int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventUserSessionsRevoked).Count(&count).Error)
		assert.GreaterOrEqual(t, count, int64(1))
	})

	t.Run("a missing user is rejected", func(t *testing.T) {
		_, err := c.RevokeUserSessions(ctx, 1, 999)
		require.Error(t, err)
	})

	t.Run("user ID zero is rejected", func(t *testing.T) {
		_, err := c.RevokeUserSessions(ctx, 1, 0)
		require.Error(t, err)
	})
}
