package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const mfaTestPassword = "Secret#Passw0rd!"

// newMFATestCore builds a core over real SQLite with an enabled encryptor (so the
// at-rest encryption of the TOTP secret is exercised) and a fixed clock (so TOTP
// codes are deterministic). Seeds user id 1 = "alice".
func newMFATestCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MFASecret{},
		&models.MFARecoveryCode{}, &models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{}))
	hash, _ := bcrypt.GenerateFromPassword([]byte(mfaTestPassword), bcrypt.DefaultCost)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetAuthEncryptor(enc)
	return c, db, fixed
}

func TestMFA_FullFlow(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	// ── Enrol ──
	uri, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	assert.Contains(t, uri, "otpauth://totp/")
	require.NotEmpty(t, secret)

	// The secret is encrypted at rest — the stored bytes are not the base32 secret.
	row, err := c.storage.GetMFASecret(ctx, 1)
	require.NoError(t, err)
	assert.NotEqual(t, secret, string(row.SecretEnc), "TOTP secret must be encrypted at rest")
	assert.False(t, row.Activated)

	// ── Activate ──
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	codes, err := c.ActivateMFA(ctx, 1, code)
	require.NoError(t, err)
	assert.Len(t, codes, 10)

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.True(t, user.MFAEnabled)

	// Activating with a wrong code earlier would have failed.
	// ── Login now demands MFA ──
	session, u, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: mfaTestPassword})
	require.ErrorIs(t, err, ErrMFARequired)
	assert.Nil(t, session)
	require.NotNil(t, u)

	// ── Verify: wrong code rejected (burns that challenge) ──
	ch1, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, err = c.VerifyMFALogin(ctx, ch1, "000000", "ua", "1.2.3.4")
	require.Error(t, err)

	// ── Verify: correct code → session ──
	ch2, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code2, _ := totp.GenerateCode(secret, fixed)
	sess, _, err := c.VerifyMFALogin(ctx, ch2, code2, "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, sess)

	// A consumed challenge can't be reused.
	_, _, err = c.VerifyMFALogin(ctx, ch2, code2, "ua", "1.2.3.4")
	require.Error(t, err, "challenge is single-use")

	// ── Recovery code: works once, then fails ──
	ch3, _ := c.CreateMFAChallenge(ctx, 1)
	sess3, _, err := c.VerifyMFALogin(ctx, ch3, codes[0], "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, sess3)

	ch4, _ := c.CreateMFAChallenge(ctx, 1)
	_, _, err = c.VerifyMFALogin(ctx, ch4, codes[0], "ua", "1.2.3.4")
	require.Error(t, err, "recovery code is single-use")

	// ── Disable via password → MFA off, secret cleared ──
	require.NoError(t, c.DisableMFA(ctx, 1, mfaTestPassword))
	require.NoError(t, db.First(&user, 1).Error)
	assert.False(t, user.MFAEnabled)
	_, err = c.storage.GetMFASecret(ctx, 1)
	require.Error(t, err, "secret removed on disable")
}

func TestMFA_ActivateRejectsWrongCode(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	ctx := context.Background()
	_, _, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, "000000")
	require.Error(t, err)
	u, err := c.storage.GetUser(ctx, 1)
	require.NoError(t, err)
	assert.False(t, u.MFAEnabled, "a failed activation must not enable MFA")
}
