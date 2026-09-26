// user_notfound_test.go — regression coverage for #504: sso.go, scim.go,
// users.go, and setup_consume.go used to detect "user not found" by string-matching
// LocalStorage's i18n error text. This file proves the shared storage.IsUserNotFound
// primitive those call sites now use is correct, using real errors -- a genuine
// sqlite miss for LocalStorage, not a hand-rolled mock error.
//
// Originally also covered the RemoteStorage half of the same fix (a genuine 404
// round-tripped through remote.HTTPClient/store.RemoteStorage); that half was
// deleted in ADR-108 Phase 6 step 14b-2 along with RemoteStorage itself.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestIsUserNotFound_RealLocalStorage proves storage.IsUserNotFound recognizes a
// genuine LocalStorage miss for every one of the lookup methods #504's call sites use
// (GetUser, GetUserByEmail, GetUserByUsername, GetUserByExternalID, RestoreUser) — all
// against a real sqlite DB, not a hand-rolled mock error.
func TestIsUserNotFound_RealLocalStorage(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	local := store.NewLocalStorage(db)
	ctx := context.Background()

	_, err = local.GetUser(ctx, 999999)
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUser miss must be detected; got: %v", err)

	_, err = local.GetUserByEmail(ctx, "ghost@nowhere.test")
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUserByEmail miss must be detected; got: %v", err)

	_, err = local.GetUserByUsername(ctx, "ghost")
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUserByUsername miss must be detected; got: %v", err)

	_, err = local.GetUserByExternalID(ctx, "sso:none:none")
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUserByExternalID miss must be detected; got: %v", err)

	err = local.RestoreUser(ctx, 999999)
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "RestoreUser miss must be detected; got: %v", err)

	// Negative: an existing user is not "not found".
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "carol", Email: "carol@example.com"}).Error)
	u, err := local.GetUser(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), u.ID)
}
