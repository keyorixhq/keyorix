// inactive_spare_new_accounts_test.go — #3740: the dashboard's "inactive users" count must not
// include an account created minutes ago that has not logged in yet. SQLite always; PostgreSQL
// when KEYORIX_TEST_PG_DSN is set.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

func newUserPGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "inactive_spare_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if d, e := db.DB(); e == nil {
			_ = d.Close()
		}
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if a, e := admin.DB(); e == nil {
			_ = a.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(&models.User{}))
	return NewLocalStorage(db)
}

func runInactiveSpareNewAccounts(t *testing.T, ls *LocalStorage) {
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(name string, createdAgo time.Duration, loginAgo *time.Duration) {
		u := &models.User{Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io"}
		u.CreatedAt = now.Add(-createdAgo)
		created, err := ls.CreateUser(ctx, u)
		require.NoError(t, err)
		if loginAgo != nil {
			require.NoError(t, ls.UpdateLastLogin(ctx, created.ID, now.Add(-*loginAgo)))
		}
	}
	old := 40 * 24 * time.Hour
	recent := 24 * time.Hour
	mk("new-never", time.Minute, nil)            // created now, never logged in
	mk("old-never", 31*24*time.Hour, nil)        // created 31 days ago, never logged in
	mk("stale-login", 90*24*time.Hour, &old)     // last login 40 days ago
	mk("fresh-login", 90*24*time.Hour, &recent)  // last login yesterday
	mk("mid-stale-login", 45*24*time.Hour, &old) // login older than the window still counts

	cutoff := now.Add(-30 * 24 * time.Hour)
	names := func(f *storage.UserFilter) map[string]bool {
		f.Page, f.PageSize = 1, 50
		users, total, err := ls.ListUsers(ctx, f)
		require.NoError(t, err)
		require.Equal(t, int64(len(users)), total)
		out := map[string]bool{}
		for _, u := range users {
			out[u.Username] = true
		}
		return out
	}

	spared := names(&storage.UserFilter{InactiveSince: &cutoff, InactiveSpareNewAccounts: true})
	assert.False(t, spared["new-never"], "an account created a minute ago is not dormant")
	assert.True(t, spared["old-never"], "never logged in and older than the window is dormant")
	assert.True(t, spared["stale-login"], "an old last_login_at is dormant")
	assert.True(t, spared["mid-stale-login"])
	assert.False(t, spared["fresh-login"])
	assert.Len(t, spared, 3)

	// The default is unchanged for the other InactiveSince callers (user list filters).
	legacy := names(&storage.UserFilter{InactiveSince: &cutoff})
	assert.True(t, legacy["new-never"], "default InactiveSince still counts every never-logged-in user")
	assert.Len(t, legacy, 4)

	// The flag does nothing without InactiveSince.
	assert.Len(t, names(&storage.UserFilter{InactiveSpareNewAccounts: true}), 5)
}

func TestListUsersInactiveSpareNewAccounts_SQLite(t *testing.T) {
	runInactiveSpareNewAccounts(t, newUserTestStore(t))
}

func TestListUsersInactiveSpareNewAccounts_Postgres(t *testing.T) {
	runInactiveSpareNewAccounts(t, newUserPGStore(t))
}
