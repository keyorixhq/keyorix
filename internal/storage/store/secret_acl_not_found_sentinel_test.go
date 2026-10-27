package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newSecretACLSentinelStore returns a LocalStorage whose schema is migrated only
// when migrate is true: an unmigrated store makes every lookup fail with a genuine
// storage error ("no such table"), never gorm.ErrRecordNotFound.
func newSecretACLSentinelStore(t *testing.T, migrate bool) *LocalStorage {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	if migrate {
		require.NoError(t, db.AutoMigrate(&models.SecretACL{}))
	}
	return NewLocalStorage(db)
}

// ERRLOSS-ACL-1: a missing ACL row wraps ErrSecretACLNotFound and keeps the exact
// legacy text ("<ErrorNotFound>: record not found").
func TestGetSecretACL_MissingRowWrapsSentinel(t *testing.T) {
	ls := newSecretACLSentinelStore(t, true)

	_, err := ls.GetSecretACL(context.Background(), 4242, 7)
	require.Error(t, err)
	assert.True(t, storage.IsSecretACLNotFound(err), "GetSecretACL(missing) must wrap ErrSecretACLNotFound: %v", err)
	assert.Equal(t, i18n.T("ErrorNotFound", nil)+": record not found", err.Error())
}

// ERRLOSS-ACL-1: a genuine storage failure (here: no table; a cancelled context
// too) is a retrieval failure, never "no ACL row". Before the fix every error was
// wrapped as ErrorNotFound, which the authorization check read as "no grant".
func TestGetSecretACL_StorageFailureIsNotSentinel(t *testing.T) {
	ls := newSecretACLSentinelStore(t, false)

	_, err := ls.GetSecretACL(context.Background(), 1, 1)
	require.Error(t, err)
	assert.False(t, storage.IsSecretACLNotFound(err), "storage failure must not be ErrSecretACLNotFound: %v", err)
	assert.Contains(t, err.Error(), i18n.T("ErrorRetrievalFailed", nil))

	migrated := newSecretACLSentinelStore(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = migrated.GetSecretACL(ctx, 1, 1)
	require.Error(t, err)
	assert.False(t, storage.IsSecretACLNotFound(err), "cancelled context must not be ErrSecretACLNotFound: %v", err)
}

// The sentinel survives one more %w wrap and is not matched by an unrelated error
// that merely carries the same text.
func TestIsSecretACLNotFound_MatchesOnlyTheSentinel(t *testing.T) {
	assert.False(t, storage.IsSecretACLNotFound(nil))
	assert.True(t, storage.IsSecretACLNotFound(fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", storage.ErrSecretACLNotFound))))
	assert.False(t, storage.IsSecretACLNotFound(gorm.ErrRecordNotFound), "gorm's own error is not the sentinel")
}
