package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestGetWebAuthnCredentialByCredID_ScopedToOwner pins the ownership boundary
// directly into GetWebAuthnCredentialByCredID's SQL (#307): CredentialID has a
// DB-level unique index, so today the query is only "safe" because its sole
// caller (persistUpdatedCredential) immediately re-checks row.UserID != userID
// after the fetch. A future caller that forgets that manual check would leak
// another user's credential blob. The fix folds the ownership check into the
// query itself (AND user_id = ?), so correctness no longer depends on every
// future caller remembering to re-check.
func TestGetWebAuthnCredentialByCredID_ScopedToOwner(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.WebAuthnCredential{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)

	ls := NewLocalStorage(db)
	ctx := context.Background()
	credID := []byte("cred-1")
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: 1, CredentialID: credID, Name: "alice's key", CredentialBlob: []byte(`{}`),
	}))

	// The owner can fetch their own credential by credential ID.
	got, err := ls.GetWebAuthnCredentialByCredID(ctx, credID, 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), got.UserID)

	// A different user presenting the SAME credential ID (e.g. a caller that
	// forgot to re-check ownership after the fetch) must get "not found", not
	// user 1's credential row.
	_, err = ls.GetWebAuthnCredentialByCredID(ctx, credID, 2)
	require.Error(t, err, "a non-owner must not be able to fetch another user's credential by credential ID")

	// An unknown credential ID is also "not found".
	_, err = ls.GetWebAuthnCredentialByCredID(ctx, []byte("no-such-cred"), 1)
	require.Error(t, err)
}

// TestLockWebAuthnCredentialForUpdate_ScopedToOwner pins the same ownership
// boundary on the locking read used by persistUpdatedCredential's atomic
// counter update (#306): the row lock must never hand back another user's
// credential.
func TestLockWebAuthnCredentialForUpdate_ScopedToOwner(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.WebAuthnCredential{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)

	ls := NewLocalStorage(db)
	ctx := context.Background()
	credID := []byte("cred-1")
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: 1, CredentialID: credID, Name: "alice's key", CredentialBlob: []byte(`{}`),
	}))

	got, err := ls.LockWebAuthnCredentialForUpdate(ctx, credID, 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), got.UserID)

	_, err = ls.LockWebAuthnCredentialForUpdate(ctx, credID, 2)
	require.Error(t, err, "a non-owner must not be able to lock another user's credential by credential ID")
}
