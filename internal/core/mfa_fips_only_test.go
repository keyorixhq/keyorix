package core

import (
	"context"
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fipsTOTPText is ErrTOTPUnavailableInFIPSMode's text. The red-proof test below
// matches on it (not on the symbol) so it compiles against the pre-fix tree.
const fipsTOTPText = "TOTP is not available in FIPS mode"

// noPanic runs f and fails the test (instead of crashing the binary) if it panics.
func noPanic(t *testing.T, name string, f func() error) error {
	t.Helper()
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked under fips140=only: %v", name, r)
			}
		}()
		err = f()
	}()
	return err
}

// FIPS-TAILS-2 item 1, red/green: under GODEBUG=fips140=only every TOTP
// verification used to panic (crypto/hmac refuses SHA-1). Each entry point must
// now answer with the typed refusal instead. Only meaningful in that mode; the
// default-mode twin below drives the same paths through the test seam.
func TestTOTP_UnderFIPS140Only_RefusedNotPanic(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; TestTOTP_FIPSRefusal_* cover the paths in default mode")
	}
	ctx := context.Background()

	t.Run("enrol", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		err := noPanic(t, "BeginMFAEnrollment", func() error { _, _, err := c.BeginMFAEnrollment(ctx, 1); return err })
		require.Error(t, err)
		assert.Contains(t, err.Error(), fipsTOTPText)
	})
	t.Run("activate", func(t *testing.T) {
		c, db, _ := newMFATestCore(t)
		// The pending secret must exist for the pre-fix code to reach the HMAC.
		_, _, err := c.BeginMFAEnrollment(ctx, 1)
		if err != nil {
			require.Contains(t, err.Error(), fipsTOTPText)
			require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x")}).Error)
		}
		err = noPanic(t, "ActivateMFA", func() error { _, err := c.ActivateMFA(ctx, 1, "123456", mfaTestPassword, ""); return err })
		require.Error(t, err)
		assert.Contains(t, err.Error(), fipsTOTPText)
	})
	t.Run("login", func(t *testing.T) {
		c, db, _ := newMFATestCore(t)
		seedActivatedTOTP(t, c, db)
		ch, err := c.CreateMFAChallenge(ctx, 1)
		require.NoError(t, err)
		err = noPanic(t, "VerifyMFALogin", func() error { _, _, _, err := c.VerifyMFALogin(ctx, ch, "123456", "ua", "1.2.3.4"); return err })
		require.Error(t, err)
		assert.Contains(t, err.Error(), fipsTOTPText)
	})
	t.Run("stepup", func(t *testing.T) {
		c, db, _ := newMFATestCore(t)
		seedActivatedTOTP(t, c, db)
		err := noPanic(t, "VerifyMFAStepUp", func() error { return c.VerifyMFAStepUp(ctx, 1, "123456") })
		require.Error(t, err)
		assert.Contains(t, err.Error(), fipsTOTPText)
	})
	t.Run("reauth", func(t *testing.T) {
		c, db, _ := newMFATestCore(t)
		seedActivatedTOTP(t, c, db)
		err := noPanic(t, "DisableMFA", func() error { return c.DisableMFA(ctx, 1, "123456", "") })
		require.Error(t, err)
		assert.Contains(t, err.Error(), fipsTOTPText)
	})
}

// seedActivatedTOTP gives alice an activated TOTP secret in either mode. Under
// fips140=only BeginMFAEnrollment refuses (after the fix), so the row is written
// directly; verification never gets to decrypt it.
func seedActivatedTOTP(t *testing.T, c *KeyorixCore, db *gorm.DB) {
	t.Helper()
	if _, _, err := c.BeginMFAEnrollment(context.Background(), 1); err != nil {
		require.Contains(t, err.Error(), fipsTOTPText)
		require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x"), Activated: true}).Error)
	} else {
		require.NoError(t, db.Model(&models.MFASecret{}).Where("user_id = ?", 1).Update("activated", true).Error)
	}
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("mfa_enabled", true).Error)
}
