// mfa_stepup.go — explicit MFA step-up verification for an already-authenticated
// user. Allows re-verifying a TOTP code (or recovery code) without going through
// re-login, creating an MFAStepUpGrant that satisfies the
// checkRestrictedMFAGate for reading "restricted" classified secrets.
package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// VerifyMFAStepUp verifies a TOTP code (or recovery code) for an authenticated
// user and, on success, creates an MFAStepUpGrant that enables reading
// restricted secrets for the configured window (default 15 min).
// Mirrors the TOTP-path of VerifyMFACredentials: loadTOTPSecret +
// validateTOTPStep + MarkTOTPStepUsed for anti-replay, recovery-code fallback,
// and the same per-account lockout the login second factor feeds.
func (c *KeyorixCore) VerifyMFAStepUp(ctx context.Context, userID uint, code string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled on this account; enrol with 'keyorix auth mfa enroll' first")
	}

	if !c.verifyMFAStepUpCode(ctx, userID, code) {
		c.auditMFAFailed(ctx, userID, "stepup")
		c.recordFailedLogin(ctx, user)
		return fmt.Errorf("invalid code")
	}

	if err := c.checkLockAndClearLoginFailures(ctx, user); err != nil {
		return err
	}

	grant := &models.MFAStepUpGrant{
		UserID:    userID,
		ExpiresAt: c.now().Add(c.mfaStepUpWindow()),
	}
	if err := c.storage.CreateMFAStepUpGrant(ctx, grant); err != nil {
		return fmt.Errorf("failed to record MFA step-up: %w", err)
	}
	uid := userID
	c.writeAuditEvent(ctx, "mfa.stepup_verified", &uid, nil,
		fmt.Sprintf("user %d completed MFA step-up for restricted secret access", userID))
	return nil
}

// verifyMFAStepUpCode checks code against the user's TOTP secret, falling
// back to a recovery code, mirroring the login second-factor verification.
func (c *KeyorixCore) verifyMFAStepUpCode(ctx context.Context, userID uint, code string) bool {
	if secret, serr := c.loadTOTPSecret(ctx, userID); serr == nil {
		if step, ok := c.validateTOTPStep(secret, code); ok {
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, userID, step); ferr == nil && fresh {
				return true
			}
		}
	}
	consumed, cerr := c.storage.ConsumeMFARecoveryCode(ctx, userID, sha256Hex(normalizeRecoveryCode(code)), c.now())
	return cerr == nil && consumed
}

// HasActiveMFAStepUp reports whether userID holds a current, unexpired step-up
// grant. Returns (false, nil) — not an error — when no grant exists.
func (c *KeyorixCore) HasActiveMFAStepUp(ctx context.Context, userID uint) (bool, error) {
	grant, err := c.storage.GetActiveMFAStepUpGrant(ctx, userID, c.authEffectiveNow())
	if err != nil {
		return false, err
	}
	return grant != nil, nil
}

// DefaultMFAStepUpGrantRetention is the fallback MFAStepUpGrant retention
// window (config.ClassificationConfig.MFAStepUpGrantRetentionDays, 0 = this
// default) used when PruneMFAStepUpGrants is called with a non-positive
// retention.
const DefaultMFAStepUpGrantRetention = 30 * 24 * time.Hour

// PruneMFAStepUpGrants removes MFAStepUpGrant rows that expired more than
// `retention` ago (retention <= 0 falls back to
// DefaultMFAStepUpGrantRetention). `before`, when non-zero and EARLIER than
// the retention-derived cutoff, narrows the deletion window further —
// mirroring PruneLoginAttempts's clamp (CORE-RATE-003): the effective cutoff
// can never be LATER than now-retention, so a caller (including
// server/http/handlers/mfa_stepup_proxy.go's PruneMFAStepUpGrantsProxy, the
// only other caller, decoding a request body from a RemoteStorage spoke node)
// can only narrow the window, never widen it into an unbounded wipe. Returns
// the number of rows removed.
//
// Unlike PruneLoginAttempts, this does NOT emit an audit event. LoginAttempt
// rows are themselves the sole record that a login/rate-limit event ever
// happened, so PruneLoginAttempts audits every deletion (mirroring
// PurgeExpiredSoftDeletes/PurgeExpiredComplianceRecords). An MFAStepUpGrant
// row is different: its CREATION is already permanently, independently
// audited (VerifyMFAStepUp emits mfa.stepup_verified, and audit events are
// append-only / never purged — ADR-029), so the grant row itself is a
// short-lived operational copy, not the sole evidentiary record. Losing N of
// these to routine maintenance is unremarkable; a log line is proportionate
// to the lower stakes.
func (c *KeyorixCore) PruneMFAStepUpGrants(ctx context.Context, retention time.Duration, before time.Time) (int64, error) {
	if retention <= 0 {
		retention = DefaultMFAStepUpGrantRetention
	}
	cutoff := c.now().Add(-retention)
	if !before.IsZero() && before.Before(cutoff) {
		cutoff = before
	}

	n, err := c.storage.PruneMFAStepUpGrants(ctx, cutoff)
	if err != nil {
		return n, err
	}
	if n > 0 {
		log.Printf("MFA step-up grant prune removed %d row(s) expired before %s", n, cutoff.UTC().Format(time.RFC3339))
	}
	return n, nil
}
