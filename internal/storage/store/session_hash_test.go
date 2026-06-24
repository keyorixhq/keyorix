package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Session tokens must be stored hashed (like PATs/setup tokens), so a database read
// never yields a live, replayable token — while the plaintext still round-trips to the
// caller and validates on lookup.
func TestSession_StoredHashedNotPlaintext(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	const raw = "kx-session-plaintext-xyz"
	created, err := ls.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: raw})
	require.NoError(t, err)
	// The caller still receives the plaintext to hand to the client.
	assert.Equal(t, raw, created.SessionToken)

	// The row stores only the hash.
	var row models.Session
	require.NoError(t, db.First(&row, created.ID).Error)
	assert.NotEqual(t, raw, row.SessionToken, "session token must not be persisted in plaintext")
	assert.Equal(t, hashSessionToken(raw), row.SessionToken)

	// Lookup by the plaintext token works (hashed internally on the way in).
	got, err := ls.GetSession(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)

	// A token equal to the stored hash (as if lifted from a DB dump) must NOT validate.
	_, err = ls.GetSession(ctx, hashSessionToken(raw))
	require.Error(t, err, "the stored hash is not itself a usable session token")
}
