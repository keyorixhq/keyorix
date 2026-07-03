package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const webauthnTestPassword = "Secret#Passw0rd!"

// newWebAuthnTestCore builds a core over real SQLite with a configured WebAuthn
// relying party and a fixed clock. Seeds user id 1 = "alice".
func newWebAuthnTestCore(t *testing.T, withRP bool) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAChallenge{}, &models.WebAuthnCredential{}, &models.WebAuthnSession{}))
	hash, _ := bcrypt.GenerateFromPassword([]byte(webauthnTestPassword), bcrypt.DefaultCost)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	if withRP {
		rp, err := webauthn.New(&webauthn.Config{
			RPID: "localhost", RPDisplayName: "Keyorix", RPOrigins: []string{"https://localhost"},
		})
		require.NoError(t, err)
		c.SetWebAuthn(rp)
	}
	return c, db
}

// seedCredential inserts a minimal stored passkey for a user and flips the flag.
func seedCredential(t *testing.T, c *KeyorixCore, db *gorm.DB, userID uint, credID string) {
	t.Helper()
	blob, _ := json.Marshal(webauthn.Credential{ID: []byte(credID)})
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: userID, CredentialID: []byte(credID), Name: "test key", CredentialBlob: blob,
	}).Error)
	require.NoError(t, c.storage.SetUserWebAuthnEnabled(context.Background(), userID, true))
}

func TestWebAuthn_LoginGateRequiresSecondFactor(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	session, u, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: webauthnTestPassword})
	require.ErrorIs(t, err, ErrMFARequired, "a passkey-enabled account must not get a session from the password step")
	assert.Nil(t, session)
	require.NotNil(t, u)
}

func TestWebAuthn_DisabledServerRejects(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, false) // no RP configured
	ctx := context.Background()
	_, _, err := c.BeginWebAuthnRegistration(ctx, 1)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
}

func TestWebAuthn_RegistrationBeginIssuesSingleUseSession(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	creation, token, err := c.BeginWebAuthnRegistration(ctx, 1)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, creation.Response.Challenge)

	// The ceremony session is stored hashed and is single-use.
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(token), c.now())
	require.NoError(t, err)
	assert.Equal(t, "register", sess.Purpose)
	_, err = c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(token), c.now())
	require.Error(t, err, "ceremony session is single-use")
}

func TestWebAuthn_BeginLoginResolvesUserFromChallenge(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	// A challenge for a user with no passkeys is rejected.
	chNoKeys, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, err = c.BeginWebAuthnLogin(ctx, chNoKeys)
	require.Error(t, err, "no passkeys registered")

	// With a passkey, begin returns assertion options + a login session token.
	seedCredential(t, c, db, 1, "cred-1")
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	assertion, token, err := c.BeginWebAuthnLogin(ctx, ch)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, assertion.Response.Challenge)
	require.Len(t, assertion.Response.AllowedCredentials, 1, "the user's passkey is in allowCredentials")

	// Begin does NOT consume the challenge (finish does).
	_, err = c.storage.GetActiveMFAChallenge(ctx, sha256Hex(ch), c.now())
	require.NoError(t, err, "the login challenge stays valid until finish")
}

func TestWebAuthn_BeginLoginRejectsBadChallenge(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")
	_, _, err := c.BeginWebAuthnLogin(ctx, "not-a-real-challenge")
	require.Error(t, err)
}

func TestWebAuthn_DeleteClearsFlagOnLastAndIsUserScoped(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	// A different user cannot delete user 1's passkey by id.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)
	require.Error(t, c.DeleteWebAuthnCredential(ctx, 2, cred.ID))

	// The owner deletes their last passkey → WebAuthn disabled.
	require.NoError(t, c.DeleteWebAuthnCredential(ctx, 1, cred.ID))
	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.False(t, user.WebAuthnEnabled, "removing the last passkey disables WebAuthn")
}

func TestWebAuthn_PasswordlessBeginIssuesSession(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	assertion, token, err := c.BeginWebAuthnPasswordlessLogin(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, assertion.Response.Challenge)
	// Usernameless: no specific credential is pre-listed (the authenticator picks).
	assert.Empty(t, assertion.Response.AllowedCredentials)
	// User verification is required so the single gesture is MFA-grade.
	assert.Equal(t, protocol.VerificationRequired, assertion.Response.UserVerification)

	// The ceremony session is stored single-use with the passwordless purpose.
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(token), c.now())
	require.NoError(t, err)
	assert.Equal(t, "passwordless", sess.Purpose)
}

func TestWebAuthn_PasswordlessDisabledServerRejects(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, false)
	ctx := context.Background()
	_, _, err := c.BeginWebAuthnPasswordlessLogin(ctx)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, "tok", "ua", "1.2.3.4", nil)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
}

func TestWebAuthn_PasswordlessFinishRejectsWrongPurposeSession(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	// A session minted for the second-factor flow must not complete a passwordless
	// login (purpose check runs before any assertion validation).
	sd := &webauthn.SessionData{Challenge: "x"}
	tok, err := c.storeWebAuthnSession(ctx, 1, "login", sd)
	require.NoError(t, err)
	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, tok, "ua", "1.2.3.4", nil)
	require.Error(t, err)

	// An unknown/expired session token is rejected too.
	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, "nope", "ua", "1.2.3.4", nil)
	require.Error(t, err)
}

// A suspended account must not complete WebAuthn second-factor login. The gate fires
// after the user is loaded but before the assertion is validated, so a suspended
// account is refused even with an otherwise-valid ceremony (nil assertion is never
// reached). Mirrors the passwordless path's existing AccountLoginBlocked gate.
func TestWebAuthn_FinishLoginRejectsSuspendedAccount(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: "x"})
	require.NoError(t, err)

	// Admin suspends the account after the ceremony began (challenge + session exist).
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", AccountSuspended).Error)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "ua", "1.2.3.4", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

// A per-account lockout (e.g. from password brute force) also bars the WebAuthn second
// factor: the gate fires before the assertion is validated, so a locked account is
// refused even with an otherwise-valid ceremony. Parity with the TOTP path.
func TestWebAuthn_FinishLoginHonorsAccountLockout(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	// The account is locked (e.g. via the password path).
	until := c.now().Add(30 * time.Minute)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("login_locked_until", until).Error)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: "x"})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "ua", "1.2.3.4", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}

// Platform authenticators (Touch ID, Windows Hello, and most passkeys) never
// implement a signature counter and always report SignCount 0. persistUpdatedCredential's
// #306 stale-write guard must not treat a (0, 0) comparison as "stale" — that would
// silently stop LastUsedAt/blob from ever persisting again after the very first login
// for the common case, mirroring go-webauthn's own Authenticator.UpdateCounter gate
// (which also special-cases 0/0 as never a clone signal).
func TestWebAuthn_PersistUpdatedCredential_ZeroCounterAuthenticatorAlwaysPersists(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	var before models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&before).Error)
	assert.Nil(t, before.LastUsedAt, "no login yet")

	// Simulate two logins in a row from a zero-counter authenticator.
	for i := 0; i < 2; i++ {
		c.now = func() time.Time { return time.Date(2026, 6, 12, 10, i, 0, 0, time.UTC) }
		c.persistUpdatedCredential(ctx, 1, &webauthn.Credential{ID: []byte("cred-1"), Authenticator: webauthn.Authenticator{SignCount: 0}})
	}

	var after models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&after).Error)
	require.NotNil(t, after.LastUsedAt, "LastUsedAt must still update on every login even when SignCount stays 0")
	assert.Equal(t, time.Date(2026, 6, 12, 10, 1, 0, 0, time.UTC), after.LastUsedAt.UTC(),
		"the SECOND login's timestamp must persist too — a (0,0) comparison must not be treated as a stale write")
}

func TestWebAuthn_FinishLoginRejectsMismatchedSession(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	// A webauthn session belonging to a different challenge/user must not pair with
	// this challenge. Create a login challenge for user 1, but a ceremony session
	// for a different user (2) — finish must reject the mismatch before any crypto.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sd := &webauthn.SessionData{Challenge: "x"}
	otherToken, err := c.storeWebAuthnSession(ctx, 2, "login", sd)
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, otherToken, "ua", "1.2.3.4", nil)
	require.Error(t, err, "a webauthn session for another user must not complete this challenge")
}
