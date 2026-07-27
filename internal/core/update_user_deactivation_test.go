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

// TestUpdateUser_Deactivation_RevokesSessionsAndPATs verifies that setting
// IsActive=false via UpdateUser immediately terminates the user's active
// sessions and PATs and evicts them from the auth cache (#r124-M).
// Prior to the fix, UpdateUser only updated the is_active column and left
// live sessions/PATs intact, so the user could keep authenticating until
// their credentials expired naturally.
func TestUpdateUser_Deactivation_RevokesSessionsAndPATs(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.PersonalAccessToken{},
		&models.AuditEvent{},
		&models.UserRole{},
		&models.Role{},
	))

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	// Seed: an active user with one session and one PAT.
	active := true
	u := &models.User{
		ID:       42,
		Username: "alice",
		Email:    "alice@example.com",
		IsActive: true,
	}
	require.NoError(t, db.Create(u).Error)
	require.NoError(t, db.Create(&models.Session{
		ID:           100,
		UserID:       42,
		SessionToken: "sess-hash-abc",
		CreatedAt:    time.Now(),
	}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{
		ID:        200,
		UserID:    42,
		Name:      "ci-token",
		TokenHash: "pat-hash-xyz",
	}).Error)

	// Track auth-cache evictions.
	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	// Deactivate via UpdateUser.
	updated, err := c.UpdateUser(ctx, &UpdateUserRequest{
		ID:       42,
		IsActive: &[]bool{false}[0],
	})
	require.NoError(t, err)
	assert.False(t, updated.IsActive, "user must be marked inactive")

	// Session must be deleted.
	var sessions []models.Session
	require.NoError(t, db.Where("user_id = ?", 42).Find(&sessions).Error)
	assert.Empty(t, sessions, "deactivation must delete all user sessions")

	// PAT must be revoked.
	var pat models.PersonalAccessToken
	require.NoError(t, db.First(&pat, 200).Error)
	assert.True(t, pat.Revoked, "deactivation must revoke all user PATs")

	// Auth cache must be evicted for both tokens.
	assert.Contains(t, evicted, "sess-hash-abc", "session hash must be evicted from auth cache")
	assert.Contains(t, evicted, "pat-hash-xyz", "PAT hash must be evicted from auth cache")

	// Re-activating should NOT revoke anything new.
	evicted = nil
	_, err = c.UpdateUser(ctx, &UpdateUserRequest{
		ID:       42,
		IsActive: &active,
	})
	require.NoError(t, err)
	assert.Empty(t, evicted, "re-activation must not evict any tokens")
}

// TestUpdateUser_NoRevocation_WhenAlreadyInactive verifies that calling
// UpdateUser on a user who is already inactive does not trigger redundant
// session/PAT revocations (the deactivating transition only fires once).
func TestUpdateUser_NoRevocation_WhenAlreadyInactive(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000&mode=2"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.PersonalAccessToken{},
		&models.AuditEvent{},
		&models.UserRole{},
		&models.Role{},
	))

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	// Seed: a user who is already inactive.
	u := &models.User{
		ID:       43,
		Username: "bob",
		Email:    "bob@example.com",
		IsActive: false,
	}
	require.NoError(t, db.Create(u).Error)

	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	// UpdateUser with IsActive=false on an already-inactive user.
	inactive := false
	_, err = c.UpdateUser(ctx, &UpdateUserRequest{
		ID:       43,
		IsActive: &inactive,
	})
	require.NoError(t, err)
	assert.Empty(t, evicted, "no evictions when user was already inactive")
}
