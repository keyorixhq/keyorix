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

// A suspended account must not complete a second factor: the challenge can be
// issued (password step passed) just before an admin suspends the account, and the
// MFA-completion path must refuse it rather than mint a session.
func TestVerifyMFALogin_RejectsSuspendedAccount(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	// Enrol + activate MFA for alice.
	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode)
	require.NoError(t, err)

	// A login is in flight (valid challenge), then the admin suspends the account.
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", AccountSuspended).Error)

	// Even a correct TOTP code must not yield a session for the suspended account.
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	sess, _, err := c.VerifyMFALogin(ctx, ch, code, "ua", "1.2.3.4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
	assert.Nil(t, sess)
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

	// A session minted before MFA is enabled must be purged on activation.
	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: "pre-mfa"}).Error)

	// ── Activate ──
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	codes, err := c.ActivateMFA(ctx, 1, code)
	require.NoError(t, err)
	assert.Len(t, codes, 10)

	var preSessions int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&preSessions).Error)
	assert.Zero(t, preSessions, "pre-enrolment sessions are invalidated on MFA activation")

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

// activateMFAForTest enrols + activates MFA for user 1 and returns the base32
// secret (for generating TOTP codes) and the initial recovery codes.
func activateMFAForTest(t *testing.T, c *KeyorixCore, fixed time.Time) (secret string, codes []string) {
	t.Helper()
	ctx := context.Background()
	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	codes, err = c.ActivateMFA(ctx, 1, code)
	require.NoError(t, err)
	return secret, codes
}

func TestMFA_RecoveryCodesRemaining(t *testing.T) {
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	// Not enabled yet → (0, 0).
	rem, total, err := c.MFARecoveryCodesRemaining(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, 0, rem)
	assert.Equal(t, 0, total)

	_, codes := activateMFAForTest(t, c, fixed)
	rem, total, err = c.MFARecoveryCodesRemaining(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, 10, rem)
	assert.Equal(t, 10, total)

	// Consume one recovery code via a login → remaining drops to 9.
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, err = c.VerifyMFALogin(ctx, ch, codes[0], "ua", "1.2.3.4")
	require.NoError(t, err)
	rem, _, err = c.MFARecoveryCodesRemaining(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, 9, rem, "one recovery code consumed")
}

func TestMFA_RegenerateRecoveryCodes(t *testing.T) {
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	secret, original := activateMFAForTest(t, c, fixed)

	// Regenerate with the password → a fresh distinct set; the old codes stop working.
	fresh, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.NoError(t, err)
	require.Len(t, fresh, 10)
	assert.NotEqual(t, original, fresh, "regenerated codes differ from the originals")

	// An OLD code no longer authenticates (the set was replaced).
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, err = c.VerifyMFALogin(ctx, ch, original[0], "ua", "1.2.3.4")
	require.Error(t, err, "old recovery codes are revoked on regenerate")

	// A NEW code works.
	ch2, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, err = c.VerifyMFALogin(ctx, ch2, fresh[1], "ua", "1.2.3.4")
	require.NoError(t, err)

	// Regenerate with a current TOTP code also works (re-auth via code path).
	totpCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, totpCode)
	require.NoError(t, err)
}

func TestMFA_RegenerateRequiresReauth(t *testing.T) {
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	_, err := c.RegenerateMFARecoveryCodes(ctx, 1, "wrong-password")
	require.Error(t, err, "regenerate must reject a bad code/password")
}

func TestMFA_RegenerateRequiresMFAEnabled(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	_, err := c.RegenerateMFARecoveryCodes(context.Background(), 1, mfaTestPassword)
	require.Error(t, err, "regenerate requires MFA to be enabled")
}

// A TOTP code must be single-use: replaying the same code within its validity window
// (with a fresh challenge) must be rejected, not mint a second session.
func TestVerifyMFALogin_RejectsReplayedTOTPCode(t *testing.T) {
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode)
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// First use succeeds.
	ch1, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, err := c.VerifyMFALogin(ctx, ch1, code, "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, sess)

	// Replay of the same code (fresh challenge, same time-step) is refused.
	ch2, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess2, _, err := c.VerifyMFALogin(ctx, ch2, code, "ua", "1.2.3.4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid code")
	assert.Nil(t, sess2)
}

// Failed second-factor attempts feed the per-account lockout, so TOTP/recovery-code
// guessing is throttled even when the per-IP limiter is bypassed (e.g. a spoofed proxy
// header). After MaxAttempts bad codes the account locks and refuses further attempts.
func TestVerifyMFALogin_FailedCodesFeedAccountLockout(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode)
	require.NoError(t, err)

	// Three wrong codes → the account locks.
	for i := 0; i < 3; i++ {
		ch, cerr := c.CreateMFAChallenge(ctx, 1)
		require.NoError(t, cerr)
		_, _, verr := c.VerifyMFALogin(ctx, ch, "000000", "ua", "9.9.9.9")
		require.Error(t, verr)
	}

	var locked models.User
	require.NoError(t, db.First(&locked, 1).Error)
	require.NotNil(t, locked.LoginLockedUntil, "account must be locked after MaxAttempts failed second factors")
	assert.True(t, locked.LoginLockedUntil.After(fixed))

	// Even a VALID code is now refused while the lock is active — second-factor guessing
	// cannot continue past the lockout.
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, err := c.VerifyMFALogin(ctx, ch, good, "ua", "9.9.9.9")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
	assert.Nil(t, sess)
}

// #125: DisableMFA accepted a TOTP-code-or-password proof with NO throttle — a caller
// holding a stolen SESSION (which doesn't itself require re-proving the second factor)
// could brute-force the 6-digit TOTP with unlimited attempts and turn MFA off
// outright. This pins that failed attempts now feed the SAME per-account lockout
// VerifyMFALogin already uses, and that even a subsequently-correct code is refused
// once locked.
func TestDisableMFA_FailedCodesFeedAccountLockout(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode)
	require.NoError(t, err)

	// Three wrong disable attempts (neither a valid TOTP code nor the password) → locked.
	for i := 0; i < 3; i++ {
		require.Error(t, c.DisableMFA(ctx, 1, "000000"))
	}

	var locked models.User
	require.NoError(t, db.First(&locked, 1).Error)
	require.NotNil(t, locked.LoginLockedUntil, "account must be locked after MaxAttempts failed disable attempts")

	// Even the CORRECT password is now refused while the lock is active.
	err = c.DisableMFA(ctx, 1, mfaTestPassword)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")

	var still models.User
	require.NoError(t, db.First(&still, 1).Error)
	assert.True(t, still.MFAEnabled, "MFA must remain enabled while the account is locked, even with the correct password")
}

// A successful disable (correct password, before any lockout) must still clear
// whatever failure count had accrued — the same convention VerifyMFALogin follows on
// a successful second factor.
func TestDisableMFA_SuccessClearsAccruedFailures(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 5, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode)
	require.NoError(t, err)

	require.Error(t, c.DisableMFA(ctx, 1, "000000"))
	require.Error(t, c.DisableMFA(ctx, 1, "111111"))

	var mid models.User
	require.NoError(t, db.First(&mid, 1).Error)
	assert.Equal(t, 2, mid.FailedLoginAttempts, "the two wrong attempts must be recorded")

	require.NoError(t, c.DisableMFA(ctx, 1, mfaTestPassword))

	var after models.User
	require.NoError(t, db.First(&after, 1).Error)
	assert.Zero(t, after.FailedLoginAttempts, "a successful disable must clear accrued failures")
}

// #125: same unthrottled-brute-force gap, same fix, for RegenerateMFARecoveryCodes.
func TestRegenerateMFARecoveryCodes_FailedCodesFeedAccountLockout(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := c.RegenerateMFARecoveryCodes(ctx, 1, "000000")
		require.Error(t, err)
	}

	var locked models.User
	require.NoError(t, db.First(&locked, 1).Error)
	require.NotNil(t, locked.LoginLockedUntil, "account must be locked after MaxAttempts failed regenerate attempts")

	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}
