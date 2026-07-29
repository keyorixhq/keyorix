// mfa_stepup.go — explicit MFA step-up verification for an already-authenticated
// user. Allows re-verifying a TOTP code (or recovery code) without going through
// re-login, minting a short-lived MFAStepupToken that satisfies the
// checkRestrictedMFAGate for reading "restricted" classified secrets.
package core

import (
	"context"
	"fmt"
)

// VerifyMFAStepUp verifies a TOTP code (or recovery code) for an authenticated
// user and, on success, upserts an MFAStepupToken that enables reading
// restricted secrets for the configured window (default 15 min).
// Mirrors the TOTP-path of VerifyMFACredentials: loadTOTPSecret +
// validateTOTPStep + MarkTOTPStepUsed for anti-replay, recovery-code fallback,
// and the same per-account lockout the login second factor feeds.
func (c *KeyorixCore) VerifyMFAStepUp(ctx context.Context, userID uint, code string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.IsActive || AccountLoginBlocked(user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled on this account; enrol with 'keyorix auth mfa enroll' first")
	}

	verified := false
	if secret, serr := c.loadTOTPSecret(ctx, userID); serr == nil {
		if step, ok := c.validateTOTPStep(secret, code); ok {
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, userID, step); ferr == nil && fresh {
				verified = true
			}
		}
	}
	if !verified {
		if consumed, cerr := c.storage.ConsumeMFARecoveryCode(ctx, userID, sha256Hex(normalizeRecoveryCode(code)), c.now()); cerr == nil && consumed {
			verified = true
		}
	}
	if !verified {
		c.auditMFAFailed(ctx, userID, "stepup")
		c.recordFailedLogin(ctx, user)
		return fmt.Errorf("invalid code")
	}

	if err := c.checkLockAndClearLoginFailures(ctx, user); err != nil {
		return err
	}

	if err := c.storage.UpsertMFAStepupToken(ctx, userID, c.now().Add(c.mfaStepUpWindow())); err != nil {
		return fmt.Errorf("failed to record MFA step-up: %w", err)
	}
	uid := userID
	c.writeAuditEvent(ctx, "mfa.stepup_verified", &uid, nil,
		fmt.Sprintf("user %d completed MFA step-up for restricted secret access", userID))
	return nil
}

// HasActiveMFAStepUp reports whether userID holds a current, unexpired step-up
// token. Returns (false, nil) — not an error — when no token exists.
func (c *KeyorixCore) HasActiveMFAStepUp(ctx context.Context, userID uint) (bool, error) {
	return c.storage.HasActiveMFAStepup(ctx, userID)
}
