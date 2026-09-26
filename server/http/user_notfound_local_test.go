package http

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestIsUserNotFound_RealLocalStorage proves the shared #504 detection primitive,
// storage.IsUserNotFound, correctly recognizes "this user does not exist" against
// a genuine gorm.ErrRecordNotFound from a real sqlite DB, wrapped by
// LocalStorage.GetUserByEmail (internal/storage/store/local_users.go).
//
// Originally a subtest of TestIsUserNotFound_RealBothBackends, which also proved
// the RemoteStorage half (a genuine 404 round-tripped through a real NewRouter-
// backed server); that half was deleted along with RemoteStorage itself in
// ADR-108 Phase 6 step 14b-2.
func TestIsUserNotFound_RealLocalStorage(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	local := store.NewLocalStorage(db)
	_, err = local.GetUserByEmail(context.Background(), "ghost-does-not-exist@example.com")
	require.Error(t, err)
	assert.True(t, storage.IsUserNotFound(err), "a genuine LocalStorage miss must be detected; got: %v", err)
}
