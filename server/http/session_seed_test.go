package http

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedSession inserts a session through the storage layer, so its token is stored
// hashed exactly as production does. A raw db.Create of a plaintext SessionToken no
// longer authenticates — GetSession looks the presented token up by its hash.
func seedSession(t *testing.T, db *gorm.DB, userID uint, token string) {
	t.Helper()
	_, err := store.NewLocalStorage(db).CreateSession(context.Background(), &models.Session{UserID: userID, SessionToken: token})
	require.NoError(t, err)
}
