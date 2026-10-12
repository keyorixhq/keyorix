package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestDeprovisionSCIMUser_RevokesSessionAndPAT is the end-to-end deprovision invariant: once
// an IdP deprovisions a user (SCIM DELETE), that user must be unable to authenticate via ANY
// credential — neither a live session token nor a personal access token. DeprovisionSCIMUser
// suspends the account, kills its sessions, and soft-deletes the user atomically; this drives
// the real flow through LocalStorage and asserts both auth paths reject the user afterward.
func TestDeprovisionSCIMUser_RevokesSessionAndPAT(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		// Role + UserRole so the precondition validations' GetUserRoles succeeds
		// (#1944: a role-lookup storage error now fails validation instead of
		// soft-failing to an empty role list).
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))

	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
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
	pu, _, _, _, err := c.ValidatePATToken(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, uint(1), pu.ID)

	// IdP deprovisions the user (actor id 2).
	require.NoError(t, c.DeprovisionSCIMUser(ctx, 2, 1))

	// Neither credential may authenticate the deprovisioned user any longer.
	_, _, err = c.ValidateSessionToken(ctx, "sess-tok")
	require.Error(t, err, "a deprovisioned user's session must not validate")
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.Error(t, err, "a deprovisioned user's PAT must not validate")

	// And the user is soft-deleted — no longer resolvable.
	_, err = ls.GetUser(ctx, 1)
	require.Error(t, err, "a deprovisioned user must be soft-deleted")

	// #2855: the two ValidatePATToken assertions above are NOT sufficient for the
	// property this test's name claims, and that is how the gap survived. A
	// deprovisioned account is login-blocked and soft-deleted, so ValidatePATToken
	// errors whether or not the PAT row was ever revoked — the assertion proved
	// INERTNESS, while the name promised REVOCATION. Assert the row.
	var unrevoked int64
	require.NoError(t, db.Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", 1, false).Count(&unrevoked).Error)
	require.Zero(t, unrevoked,
		"a deprovisioned user's PATs must be REVOKED, not merely inert: ReactivateUser and RestoreUser "+
			"revoke nothing, so an unrevoked row is handed back the moment the account is restored")
}

// TestDeprovisionSCIMUser_RestoreDoesNotHandBackPATs is #2855's own regression
// test: the consequence, driven end to end. The point is not that the PAT is
// refused while the account is deprovisioned (it always was — the account is
// blocked), but that it is still refused AFTER a restore, which is where an
// unrevoked row came back to life.
func TestDeprovisionSCIMUser_RestoreDoesNotHandBackPATs(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))

	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "bob", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}).Error)
	raw := patPrefix + "scim-restore-regression-token"
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw)}).Error)

	// Precondition: it works while the account is live.
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.NoError(t, err)

	require.NoError(t, c.DeprovisionSCIMUser(ctx, 2, 1))

	// The IdP offboard is reversed — a restored hire, a deprovision-by-mistake,
	// an IdP sync glitch. The account becomes usable again.
	require.NoError(t, c.RestoreUser(ctx, 2, 1))
	require.NoError(t, c.ReactivateUser(ctx, 2, 1))
	restored, err := ls.GetUser(ctx, 1)
	require.NoError(t, err, "the account must be live again — otherwise this test proves nothing")
	require.True(t, restored.IsActive)

	// The credential the offboarding was recorded as having removed must stay dead.
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.Error(t, err,
		"a PAT that existed at SCIM-deprovision time must not authenticate after the account is restored — "+
			"the deprovision is the only point at which it is revoked (#2855)")
	require.ErrorIs(t, err, ErrPATRevoked)
}
