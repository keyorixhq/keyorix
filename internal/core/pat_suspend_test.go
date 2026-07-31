package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestValidatePATToken_SuspendRevokesTokenAccess is the end-to-end regression for the
// suspended-PAT bypass: an admin SuspendUser sets account_state=suspended and kills the
// user's sessions, but deliberately leaves is_active true. Before the fix the user's
// personal access token kept working — suspension cut off session access but not token
// access. This drives the real flow through LocalStorage and asserts the PAT is rejected
// once the account is suspended.
func TestValidatePATToken_SuspendRevokesTokenAccess(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}, &models.Session{}, &models.AuditEvent{}))

	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive}).Error)
	raw := patPrefix + "suspend-regression-token"
	require.NoError(t, db.Create(&models.PersonalAccessToken{
		ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw), TokenPrefix: "kx",
	}).Error)

	// Precondition: the PAT validates while the account is active.
	u, _, _, err := c.ValidatePATToken(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, uint(1), u.ID)

	// Admin (id 2) suspends the user.
	require.NoError(t, c.SuspendUser(ctx, 2, 1))

	// The PAT must now be rejected — suspension actively revokes the user's PATs (not just
	// blocking them via account state), so the token is reported revoked.
	_, _, _, err = c.ValidatePATToken(ctx, raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	// Confirm the revocation is persisted (defence-in-depth, independent of the auth cache).
	var pat models.PersonalAccessToken
	require.NoError(t, db.First(&pat, 1).Error)
	assert.True(t, pat.Revoked, "suspension must revoke the user's PATs")
}
