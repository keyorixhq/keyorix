package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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

// TestRevokeUserSessions_EvictsImpersonationSessionsStarted is the #G06
// regression: RevokeUserSessions used to build its auth-cache eviction list
// from ListSessionsByUser (user_id = ? only), while the actual DB deletion
// (DeleteSessionsForUserExcept) also removes sessions the user STARTED as an
// impersonator (impersonated_by = ?). A revoked admin's own impersonation
// session was deleted from the DB but never evicted from the cache, leaving
// it live — authenticating on the fast path — until the positive-cache TTL
// expired.
func TestRevokeUserSessions_EvictsImpersonationSessionsStarted(t *testing.T) {
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

	adminID := uint(1)
	// The admin's own session.
	require.NoError(t, db.Create(&models.Session{ID: 20, UserID: 1, SessionToken: "admin-own", CreatedAt: time.Now()}).Error)
	// A session issued FOR the target user, STARTED by the admin impersonating them —
	// UserID is the target's, ImpersonatedBy is the admin's.
	require.NoError(t, db.Create(&models.Session{
		ID: 21, UserID: 2, SessionToken: "admin-impersonating-target",
		ImpersonatedBy: &adminID, CreatedAt: time.Now(),
	}).Error)

	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	n, err := c.RevokeUserSessions(ctx, 1, 1) // revoke the admin's own sessions
	require.NoError(t, err)
	assert.Equal(t, 2, n, "both the admin's own session and the impersonation session it started")

	assert.ElementsMatch(t, []string{"admin-own", "admin-impersonating-target"}, evicted,
		"the impersonation session must be evicted from the auth cache, not just deleted from the DB")

	// Both rows are actually gone from the DB too.
	var remaining int64
	require.NoError(t, db.Model(&models.Session{}).Where("id IN ?", []uint{20, 21}).Count(&remaining).Error)
	assert.Equal(t, int64(0), remaining)
}
