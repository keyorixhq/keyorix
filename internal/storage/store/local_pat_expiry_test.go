// local_pat_expiry_test.go — unit tests for LocalStorage.ListExpiredPATsByUser
// and LocalStorage.BulkRevokeExpiredPATsByUser (local_auth.go).
package store_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var patExpiryStoreSeq atomic.Int64

func newPatExpiryLocalDB(t *testing.T) *gorm.DB {
	t.Helper()
	n := patExpiryStoreSeq.Add(1)
	dsn := fmt.Sprintf("file:kx_pat_expiry_store_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}))
	return db
}

// ── ListExpiredPATsByUser ─────────────────────────────────────────────────────

func TestLocalStorage_ListExpiredPATsByUser_OnlyExpiredNonRevoked(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// ID 1: expired, non-revoked — must appear
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 5, TokenHash: "a", Name: "expired", ExpiresAt: &past, Revoked: false}).Error)
	// ID 2: active — must not appear
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 2, UserID: 5, TokenHash: "b", Name: "active", ExpiresAt: &future, Revoked: false}).Error)
	// ID 3: expired AND revoked — must not appear
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 3, UserID: 5, TokenHash: "c", Name: "exp-revoked", ExpiresAt: &past, Revoked: true}).Error)
	// ID 4: nil expiry — must not appear
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 4, UserID: 5, TokenHash: "d", Name: "no-exp", Revoked: false}).Error)
	// ID 5: different user — must not appear
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 5, UserID: 99, TokenHash: "e", Name: "other", ExpiresAt: &past, Revoked: false}).Error)

	tokens, err := ls.ListExpiredPATsByUser(ctx, 5, now)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, uint(1), tokens[0].ID)
}

func TestLocalStorage_ListExpiredPATsByUser_Empty(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)
	now := time.Now()
	tokens, err := ls.ListExpiredPATsByUser(context.Background(), 7, now)
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ── BulkRevokeExpiredPATsByUser ───────────────────────────────────────────────

func TestLocalStorage_BulkRevokeExpiredPATsByUser_RevokesExpiredAndReturnsHashes(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 10, TokenHash: "hash-a", Name: "exp1", ExpiresAt: &past, Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 2, UserID: 10, TokenHash: "hash-b", Name: "exp2", ExpiresAt: &past, Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 3, UserID: 10, TokenHash: "hash-c", Name: "active", ExpiresAt: &future, Revoked: false}).Error)

	hashes, err := ls.BulkRevokeExpiredPATsByUser(ctx, 10, now)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"hash-a", "hash-b"}, hashes)

	// Verify DB state.
	var p1, p2, p3 models.PersonalAccessToken
	require.NoError(t, db.First(&p1, 1).Error)
	require.NoError(t, db.First(&p2, 2).Error)
	require.NoError(t, db.First(&p3, 3).Error)
	assert.True(t, p1.Revoked)
	assert.True(t, p2.Revoked)
	assert.False(t, p3.Revoked)
}

func TestLocalStorage_BulkRevokeExpiredPATsByUser_NoneExpired_ReturnsNil(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)

	hashes, err := ls.BulkRevokeExpiredPATsByUser(context.Background(), 20, time.Now())
	require.NoError(t, err)
	assert.Nil(t, hashes)
}

func TestLocalStorage_BulkRevokeExpiredPATsByUser_DoesNotRevokeDifferentUser(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	// User 30's expired PAT — revoking for user 31 must NOT touch it.
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 30, TokenHash: "hash-x", Name: "other", ExpiresAt: &past, Revoked: false}).Error)

	hashes, err := ls.BulkRevokeExpiredPATsByUser(ctx, 31, now)
	require.NoError(t, err)
	assert.Nil(t, hashes)

	var p models.PersonalAccessToken
	require.NoError(t, db.First(&p, 1).Error)
	assert.False(t, p.Revoked, "other user's token must remain untouched")
}

// ── error paths (cancelled context / broken DB) ──────────────────────────────

func TestLocalStorage_ListExpiredPATsByUser_CancelledContext_ReturnsError(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ls.ListExpiredPATsByUser(ctx, 5, time.Now())
	require.Error(t, err)
}

func TestLocalStorage_BulkRevokeExpiredPATsByUser_CancelledContext_ReturnsError(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	// Seed at least one expired PAT so the Pluck returns rows and the Update path is also
	// reached. With a cancelled context, the first query (Pluck) should fail immediately.
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 5, TokenHash: "cx1", Name: "exp", ExpiresAt: &past, Revoked: false}).Error)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ls.BulkRevokeExpiredPATsByUser(ctx, 5, now)
	require.Error(t, err)
}

// TestLocalStorage_BulkRevokeExpiredPATsByUser_UpdateFails covers the error branch
// when the Pluck succeeds (matching rows exist) but the subsequent UPDATE fails.
// We inject a before-update callback that returns a sentinel error to simulate a
// transient DB failure mid-operation.
func TestLocalStorage_BulkRevokeExpiredPATsByUser_UpdateFails_ReturnsError(t *testing.T) {
	db := newPatExpiryLocalDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	// Seed an expired PAT so the Pluck finds at least one hash.
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 5, TokenHash: "uf1", Name: "exp", ExpiresAt: &past, Revoked: false}).Error)

	// Register a before-update callback that injects a sentinel error.
	sentinelErr := fmt.Errorf("injected update failure")
	require.NoError(t, ls.DB().Callback().Update().Before("gorm:before_update").Register(
		"test:fail_update_pat_expiry",
		func(d *gorm.DB) { _ = d.AddError(sentinelErr) },
	))
	t.Cleanup(func() {
		_ = ls.DB().Callback().Update().Remove("test:fail_update_pat_expiry")
	})

	_, err := ls.BulkRevokeExpiredPATsByUser(ctx, 5, now)
	require.Error(t, err)
}
