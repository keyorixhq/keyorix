package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestDeprovisionSCIMUser_RevokesSessionAndPAT is the end-to-end deprovision invariant: once
// an IdP deprovisions a user (SCIM DELETE), that user must be unable to authenticate via ANY
// credential — neither a live session token nor a personal access token. DeprovisionSCIMUser
// suspends the account, kills its sessions, and soft-deletes the user atomically; this drives
// the real flow through LocalStorage and asserts both auth paths reject the user afterward.
func TestDeprovisionSCIMUser_RevokesSessionAndPAT(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{}))

	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive}).Error)
	expiry := time.Now().Add(time.Hour)
	// Create through the storage layer so the session token is hashed at rest (raw
	// db.Create would store the plaintext, which GetSession's hashed lookup won't match).
	_, err = ls.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "sess-tok", ExpiresAt: &expiry})
	require.NoError(t, err)
	raw := patPrefix + "deprovision-regression-token"
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw)}).Error)

	// Preconditions: while active, both the session and the PAT validate.
	su, _, err := c.ValidateSessionToken(ctx, "sess-tok")
	require.NoError(t, err)
	require.Equal(t, uint(1), su.ID)
	pu, _, _, err := c.ValidatePATToken(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, uint(1), pu.ID)

	// IdP deprovisions the user (actor id 2).
	require.NoError(t, c.DeprovisionSCIMUser(ctx, 2, 1))

	// Neither credential may authenticate the deprovisioned user any longer.
	_, _, err = c.ValidateSessionToken(ctx, "sess-tok")
	require.Error(t, err, "a deprovisioned user's session must not validate")
	_, _, _, err = c.ValidatePATToken(ctx, raw)
	require.Error(t, err, "a deprovisioned user's PAT must not validate")

	// And the user is soft-deleted — no longer resolvable.
	_, err = ls.GetUser(ctx, 1)
	require.Error(t, err, "a deprovisioned user must be soft-deleted")
}
