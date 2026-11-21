// mfa_recovery_reauth_test.go — #4224: an unused recovery code re-authenticates
// DisableMFA and RegenerateMFARecoveryCodes (reauthWithRecoveryCode), consumed
// in the same transaction as the change, counted toward the lockout like a
// wrong TOTP code, and answered like a wrong code on every refusal.
package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// recoveryReauthPolicy counts failures; MaxAttempts is high enough that the
// tests below never trip it unless they mean to.
var recoveryReauthPolicy = LoginLockoutPolicy{
	Enabled: true, MaxAttempts: 10, Window: time.Hour,
	BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
}

func unusedRecoveryCodes(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.MFARecoveryCode{}).Where("user_id = ? AND used_at IS NULL", 1).Count(&n).Error)
	return n
}

func mfaEnabledInDB(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	return u.MFAEnabled
}

// armFault swaps c.storage for a FaultyStorage firing once on method.
func armFault(c *KeyorixCore, method string, kind faultstorage.FaultKind) (*faultstorage.FaultyStorage, func()) {
	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: method, NthCall: 1, Kind: kind, Err: errors.New("injected: " + method),
	})
	c.storage = fs
	return fs, func() { c.storage = base }
}

func TestDisableMFA_RecoveryCode_DisablesConsumesAndRevokesOtherSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	_, codes := activateMFAForTest(t, c, fixed)
	expiry := fixed.Add(time.Hour)
	_, err := c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "calling-session", ExpiresAt: &expiry})
	require.NoError(t, err)
	_, err = c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "lost-phone-session", ExpiresAt: &expiry})
	require.NoError(t, err)

	// Entered the forgiving way the login accepts it: lower case, no dash.
	entered := strings.ToLower(strings.ReplaceAll(codes[3], "-", ""))
	require.NoError(t, c.DisableMFA(ctx, 1, entered, "calling-session"))

	assert.False(t, mfaEnabledInDB(t, db), "MFA must be off")
	var left int64
	require.NoError(t, db.Model(&models.MFARecoveryCode{}).Where("user_id = ?", 1).Count(&left).Error)
	assert.Zero(t, left, "the disable clears every recovery code, the consumed one included")
	_, err = c.storage.GetSession(ctx, "calling-session")
	require.NoError(t, err, "the calling session survives")
	_, err = c.storage.GetSession(ctx, "lost-phone-session")
	require.Error(t, err, "every other session is revoked after a recovery-code disable")

	disabled := auditDescriptions(t, db, "mfa.disabled")
	require.Len(t, disabled, 1)
	assert.Contains(t, disabled[0], "method: recovery_code")
	reauth := auditDescriptions(t, db, "mfa.reauth_verified")
	require.NotEmpty(t, reauth)
	assert.Contains(t, reauth[len(reauth)-1], "phase: disable, method: recovery_code")
}

func TestRegenerateRecoveryCodes_RecoveryCode_ReplacesTheSetAndRecordsTheMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	_, codes := activateMFAForTest(t, c, fixed)

	fresh, err := c.RegenerateMFARecoveryCodes(ctx, 1, codes[0])
	require.NoError(t, err)
	require.Len(t, fresh, mfaRecoveryCodeCount)
	assert.True(t, mfaEnabledInDB(t, db), "regenerate leaves MFA on")
	assert.Equal(t, int64(mfaRecoveryCodeCount), unusedRecoveryCodes(t, db), "exactly the new set is unused")

	// An old, never-used code from the replaced set no longer re-authenticates.
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, codes[1])
	require.ErrorIs(t, err, ErrReauthRejected)
	// A code from the new set does.
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, fresh[0])
	require.NoError(t, err)

	regen := auditDescriptions(t, db, "mfa.recovery_codes_regenerated")
	require.Len(t, regen, 2)
	for _, d := range regen {
		assert.Contains(t, d, "method: recovery_code")
	}
}

// A wrong or already-used recovery code is refused like a wrong TOTP code:
// ErrReauthRejected, the same text, counted exactly once, audited mfa.failed,
// nothing consumed.
func TestRecoveryReauth_WrongOrUsedCodeCountsOnceLikeAWrongTOTPCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Control: a wrong TOTP code.
	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = recoveryReauthPolicy
	activateMFAForTest(t, cc, cfixed)
	cerr := cc.DisableMFA(ctx, 1, "000000", "")
	require.ErrorIs(t, cerr, ErrReauthRejected)

	for name, input := range map[string]func(codes []string, c *KeyorixCore) string{
		"wrong": func([]string, *KeyorixCore) string { return "ZZZZZ-ZZZZZ" },
		"used": func(codes []string, c *KeyorixCore) string {
			ch, err := c.CreateMFAChallenge(ctx, 1)
			require.NoError(t, err)
			_, _, _, err = c.VerifyMFALogin(ctx, ch, codes[0], "ua", "203.0.113.9")
			require.NoError(t, err, "spend the code at login first")
			return codes[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, db, fixed := newMFATestCore(t)
			c.loginLockout = recoveryReauthPolicy
			_, codes := activateMFAForTest(t, c, fixed)
			code := input(codes, c)
			before := unusedRecoveryCodes(t, db)

			err := c.DisableMFA(ctx, 1, code, "")
			require.ErrorIs(t, err, ErrReauthRejected)
			assert.Equal(t, cerr.Error(), err.Error(), "the same answer as a wrong TOTP code")
			_, err = c.RegenerateMFARecoveryCodes(ctx, 1, code)
			require.ErrorIs(t, err, ErrReauthRejected)

			assert.Equal(t, 2*failedLoginCount(t, cdb), failedLoginCount(t, db), "each attempt counted exactly once, like the control")
			assert.Len(t, auditDescriptions(t, db, "mfa.failed"), 2)
			assert.True(t, mfaEnabledInDB(t, db))
			assert.Equal(t, before, unusedRecoveryCodes(t, db), "nothing consumed")
		})
	}
}

// A locked account is refused before any code is evaluated (the row-lock half
// is TestReauthWithRecoveryCode_LockedUnderTheRowLock).
func TestRecoveryReauth_LockedAccountRefusedBeforeTheCodeIsEvaluated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = recoveryReauthPolicy
	_, codes := activateMFAForTest(t, c, fixed)
	until := time.Now().Add(time.Hour)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("login_locked_until", until).Error)

	err := c.DisableMFA(ctx, 1, codes[0], "")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Contains(t, err.Error(), "temporarily locked")
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, codes[0])
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, int64(mfaRecoveryCodeCount), unusedRecoveryCodes(t, db), "the code was not looked at")
	assert.True(t, mfaEnabledInDB(t, db))
	assert.Empty(t, auditDescriptions(t, db, "mfa.failed"))
}

// The change failing after the code matched (an error or a panic) rolls the
// whole transaction back: the code stays unused, MFA stays on, and the answer
// and the lockout cost are those of a wrong code.
func TestRecoveryReauth_ChangeFailureRollsBackAndCostsLikeAWrongCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	wrong := cc.DisableMFA(ctx, 1, "ZZZZZ-ZZZZZ", "")
	require.ErrorIs(t, wrong, ErrReauthRejected)
	control := readLockoutState(t, cdb, 1)

	cases := []struct {
		op     string
		method string
		kind   faultstorage.FaultKind
	}{
		{"disable", "DeleteMFAForUser", faultstorage.KindError},
		{"disable", "DeleteMFAForUser", faultstorage.KindPanic},
		{"regenerate", "CreateMFARecoveryCodes", faultstorage.KindError},
		{"regenerate", "CreateMFARecoveryCodes", faultstorage.KindPanic},
	}
	for _, tc := range cases {
		t.Run(tc.op+"/"+tc.method+"/"+map[faultstorage.FaultKind]string{faultstorage.KindError: "error", faultstorage.KindPanic: "panic"}[tc.kind], func(t *testing.T) {
			c, db, fixed := newMFATestCore(t)
			c.loginLockout = postVerdictParityPolicy
			_, codes := activateMFAForTest(t, c, fixed)
			putAtThresholdMinusOne(t, db, 1)
			fs, restore := armFault(c, tc.method, tc.kind)
			var err error
			if tc.op == "disable" {
				err = c.DisableMFA(ctx, 1, codes[0], "")
			} else {
				_, err = c.RegenerateMFARecoveryCodes(ctx, 1, codes[0])
			}
			restore()
			require.True(t, fs.Fired(), "the fault must have been reached")
			require.ErrorIs(t, err, ErrReauthRejected)
			assert.Equal(t, wrong.Error(), err.Error(), "byte-identical to a wrong code")

			assert.Equal(t, int64(mfaRecoveryCodeCount), unusedRecoveryCodes(t, db), "rolled back: the code is still unused")
			assert.True(t, mfaEnabledInDB(t, db), "rolled back: MFA still on")
			requireSameLockoutCost(t, control, readLockoutState(t, db, 1), tc.op+" change fault")
			assert.NotEmpty(t, auditDescriptions(t, db, "mfa.error"), "audited distinctly for an operator")
		})
	}
}

// A fault on the row lock or the consume itself reaches no verdict on the
// code: not counted, audited mfa.error, the storage-failure sentinel the
// handler answers with the wrong-code text, nothing consumed.
func TestRecoveryReauth_PreVerdictFaultIsNotCounted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, method := range []string{"LockUserForUpdate", "ConsumeMFARecoveryCode"} {
		for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
			if method == "LockUserForUpdate" && kind == faultstorage.KindPanic {
				continue // a panic there is outside the consume's recover, as for every other row-lock caller
			}
			t.Run(method+map[faultstorage.FaultKind]string{faultstorage.KindError: "/error", faultstorage.KindPanic: "/panic"}[kind], func(t *testing.T) {
				c, db, fixed := newMFATestCore(t)
				c.loginLockout = recoveryReauthPolicy
				_, codes := activateMFAForTest(t, c, fixed)
				fs, restore := armFault(c, method, kind)
				err := c.DisableMFA(ctx, 1, codes[0], "")
				restore()
				require.True(t, fs.Fired())
				require.ErrorIs(t, err, ErrMFAVerificationStorageFailure)
				assert.False(t, errors.Is(err, ErrReauthRejected), "nothing evaluated: the handler hands the slot back")
				assert.Zero(t, failedLoginCount(t, db), "not counted")
				assert.Empty(t, auditDescriptions(t, db, "mfa.failed"))
				assert.NotEmpty(t, auditDescriptions(t, db, "mfa.error"))
				assert.Equal(t, int64(mfaRecoveryCodeCount), unusedRecoveryCodes(t, db))
				assert.True(t, mfaEnabledInDB(t, db))
			})
		}
	}
}

// Two concurrent requests with the same recovery code: exactly one succeeds.
func TestRecoveryReauth_ConcurrentSameCodeExactlyOneSucceeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, op := range []string{"disable", "regenerate"} {
		t.Run(op, func(t *testing.T) {
			c, db, fixed := newMFATestCore(t)
			c.loginLockout = recoveryReauthPolicy
			// One connection: the in-memory database is per connection.
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(1)
			_, codes := activateMFAForTest(t, c, fixed)

			const n = 8
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make([]error, n)
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if op == "disable" {
						errs[i] = c.DisableMFA(ctx, 1, codes[0], "")
					} else {
						_, errs[i] = c.RegenerateMFARecoveryCodes(ctx, 1, codes[0])
					}
				}()
			}
			close(start)
			wg.Wait()
			ok := 0
			for _, e := range errs {
				if e == nil {
					ok++
				} else {
					assert.Contains(t, []string{"invalid code or password", "MFA is not enabled"}, reauthAnswerText(e), "a loser gets a refusal, never a second success")
				}
			}
			assert.Equal(t, 1, ok, "exactly one request may use the code")
		})
	}
}

// reauthAnswerText is the text the HTTP handler answers with (writeMFAErr):
// a storage-failure sentinel answers like a wrong code.
func reauthAnswerText(err error) string {
	if errors.Is(err, ErrMFAVerificationStorageFailure) {
		return "invalid code or password"
	}
	return err.Error()
}

// FIPS 140-only mode: a TOTP code is refused before evaluation (unchanged,
// TestTOTP_FIPSRefusal_PreVerdictOnEveryPath), and a recovery code works
// exactly as without FIPS, as at login and step-up: accepted and consumed, or
// refused and counted.
func TestRecoveryReauth_FIPSModeAcceptsRecoveryCodesAndCountsWrongOnes(t *testing.T) { //nolint:paralleltest // forceTOTPFIPS swaps a package variable
	ctx := context.Background()
	c, db, _ := newMFATestCore(t)
	c.loginLockout = recoveryReauthPolicy
	seedActivatedTOTP(t, c, db)
	codes, hashes, err := generateRecoveryCodes(3)
	require.NoError(t, err)
	for _, h := range hashes {
		require.NoError(t, db.Create(&models.MFARecoveryCode{UserID: 1, CodeHash: h}).Error)
	}
	forceTOTPFIPS(t)

	err = c.DisableMFA(ctx, 1, "123456", "")
	require.ErrorIs(t, err, ErrTOTPUnavailableInFIPSMode, "a TOTP code is still refused unevaluated")
	assert.Zero(t, failedLoginCount(t, db))

	err = c.DisableMFA(ctx, 1, "ZZZZZ-ZZZZZ", "")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, 1, failedLoginCount(t, db), "a wrong recovery code is counted in FIPS mode too")

	fresh, err := c.RegenerateMFARecoveryCodes(ctx, 1, codes[0])
	require.NoError(t, err, "a recovery code re-authenticates in FIPS mode")
	require.NoError(t, c.DisableMFA(ctx, 1, fresh[0], ""))
	assert.False(t, mfaEnabledInDB(t, db))
	assert.Contains(t, auditDescriptions(t, db, "mfa.disabled")[0], "method: recovery_code")
}

// The password alone still does not re-authenticate an account with a second
// factor, and a recovery code is accepted only by disable and regenerate, not
// by requireReauth's other callers.
func TestRecoveryReauth_PasswordAloneStillRefusedAndOtherCallersUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	_, codes := activateMFAForTest(t, c, fixed)

	require.ErrorIs(t, c.DisableMFA(ctx, 1, mfaTestPassword, ""), ErrReauthRejected)
	_, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.ErrorIs(t, err, ErrReauthRejected)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.ErrorIs(t, c.requireReauth(ctx, &u, codes[0], "webauthn_delete"), ErrReauthRejected,
		"requireReauth itself does not take a recovery code")
	assert.Equal(t, int64(mfaRecoveryCodeCount), unusedRecoveryCodes(t, db), "nothing consumed")
	assert.True(t, mfaEnabledInDB(t, db))
}

// A password that happens to look like a recovery code still works with a
// reauth step-up grant, as before: no recovery code matches, so the input goes
// on to requireReauth.
func TestRecoveryReauth_RecoveryShapedPasswordWithGrantStillWorks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	activateMFAForTest(t, c, fixed)
	const shaped = "PQRST-23456" // recovery-shaped: TestIsRecoveryCodeShaped
	hash, err := bcrypt.GenerateFromPassword([]byte(shaped), int(bcryptCost.Load()))
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("password_hash", string(hash)).Error)
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: time.Now().Add(time.Hour)}).Error)

	require.NoError(t, c.DisableMFA(ctx, 1, shaped, ""))
	assert.False(t, mfaEnabledInDB(t, db))
	assert.NotContains(t, auditDescriptions(t, db, "mfa.disabled")[0], "method:", "not a recovery-code disable")
}

// An account owing an enrolment after an administrator reset, or with only a
// passkey, has no TOTP factor: disable and regenerate answer as before.
func TestRecoveryReauth_NoTOTPFactorAnswersAsBefore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, _ := newMFATestCore(t)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).
		Updates(map[string]any{"mfa_enrolment_required": true, "web_authn_enabled": true}).Error)
	_, hashes, err := generateRecoveryCodes(1)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.MFARecoveryCode{UserID: 1, CodeHash: hashes[0]}).Error)

	err = c.DisableMFA(ctx, 1, "ZZZZZ-ZZZZZ", "")
	require.EqualError(t, err, "MFA is not enabled")
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, "ZZZZZ-ZZZZZ")
	require.EqualError(t, err, "MFA is not enabled")
}
