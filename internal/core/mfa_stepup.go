// mfa_stepup.go — explicit MFA step-up verification for an already-authenticated
// user. Allows re-verifying a TOTP code (or recovery code) without going through
// re-login, creating an MFAStepUpGrant that satisfies the
// checkRestrictedMFAGate for reading "restricted" classified secrets.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
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

	// storageErr distinguishes a genuine storage-read/write failure from a
	// CONFIRMED negative result (wrong code / non-matching recovery code),
	// mirroring VerifyMFACredentials' own storageErr handling (#2548): a
	// resolution error here must not be indistinguishable from a legitimate
	// negative result, or it both wrongly reports "invalid code" and wrongly
	// counts toward the account lockout for a code that was never actually
	// checked. verifyMFAStepUpCode used to collapse both cases into a single
	// bool, which is exactly the bug #2548 fixed for the login path but never
	// reached here — this is that same sibling, found during the FIX-1 sweep.
	verified, storageErr := c.verifyMFAStepUpCode(ctx, userID, code)
	if !verified {
		if storageErr != nil {
			c.auditMFAError(ctx, userID, "stepup", storageErr)
			// #2888 (#2740 option C extended to lockout bookkeeping): when the
			// code WAS confirmed correct and only a subsequent write (the
			// anti-replay mark) failed, verifyMFAStepUpCode does NOT wrap this
			// error with ErrMFAVerificationUnavailable (unlike the genuinely
			// pre-verdict case) -- that is exactly the signal used here to still
			// count it toward the lockout, same as a wrong code would be. A
			// correct guess must never be cheaper, lockout-wise, than a wrong one.
			if !errors.Is(storageErr, ErrMFAVerificationUnavailable) {
				c.recordFailedLogin(ctx, user)
			}
			return fmt.Errorf("%w: %s: %w", ErrMFAVerificationStorageFailure, i18n.T("ErrorRetrievalFailed", nil), storageErr)
		}
		c.auditMFAFailed(ctx, userID, "stepup")
		c.recordFailedLogin(ctx, user)
		return fmt.Errorf("invalid code")
	}

	// TOCTOU re-check only — the failure state is NOT cleared here (#2894): the
	// step-up grant below is still to be written, and a fault there denies the
	// step-up while leaving the counter at 0, making a CORRECT code the cheaper
	// probe than a wrong one. See LoginCompletion.
	if err := c.recheckLoginLockFailClosed(ctx, user); err != nil {
		return err
	}

	grant := &models.MFAStepUpGrant{
		UserID:    userID,
		Purpose:   models.MFAStepUpPurposeRestrictedSecretRead,
		ExpiresAt: c.now().Add(c.mfaStepUpWindow()),
	}
	if err := c.storage.CreateMFAStepUpGrant(ctx, grant); err != nil {
		// #2894: the code already verified, so count this post-verdict storage
		// fault exactly as a wrong code would be counted (recordFailedLogin above).
		return c.denyAfterCredentialMatched(ctx, user, fmt.Errorf("failed to record MFA step-up: %w", err))
	}
	c.clearLoginFailures(ctx, user)
	uid := userID
	c.writeAuditEvent(ctx, "mfa.stepup_verified", &uid, nil,
		fmt.Sprintf("user %d completed MFA step-up for restricted secret access", userID))
	return nil
}

// atomicity: consume-first by design (Session O, O4) — the TOTP step (or
// recovery code) is consumed BEFORE VerifyMFAStepUp creates the
// MFAStepUpGrant. A later grant-creation failure must not un-consume it:
// verified by TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed
// (consume_first_fails_closed_test.go), which injects a CreateMFAStepUpGrant
// failure after a successful consume and confirms no grant is issued and the
// code stays consumed.
//
// verifyMFAStepUpCode checks code against the user's TOTP secret, falling
// back to a recovery code, mirroring the login second-factor verification.
// Returns (true, nil) on a confirmed match, (false, nil) on a confirmed
// negative result (the code genuinely doesn't match either path), and
// (false, err) on a storage failure -- err is wrapped with
// ErrMFAVerificationUnavailable only when NEITHER path reached a verdict at
// all (codeMatched stays false); the caller (VerifyMFAStepUp) uses exactly
// that wrap to decide whether to count the attempt toward the lockout (#2888
// round 2: a code confirmed correct, with only its anti-replay MarkTOTPStepUsed
// write failing, still counts, exactly like a wrong code would -- it must
// never be cheaper, lockout-wise, than a genuine bad guess, even though the
// RESPONSE this produces is already identical to a wrong code either way).
// The recovery-code path is tried regardless of a TOTP-phase storage error,
// same as VerifyMFACredentials: the caller may have supplied a recovery code,
// not a TOTP code, and a failed TOTP secret read must not preempt a
// genuinely valid recovery code.
func (c *KeyorixCore) verifyMFAStepUpCode(ctx context.Context, userID uint, code string) (bool, error) {
	var storageErr error
	codeMatched := false // see VerifyMFACredentials / ErrMFAVerificationUnavailable
	if secret, serr := c.loadTOTPSecret(ctx, userID); serr != nil {
		storageErr = serr
	} else if step, ok := c.validateTOTPStep(secret, code); ok {
		codeMatched = true
		if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, userID, step); ferr != nil {
			storageErr = ferr
		} else if fresh {
			return true, nil
		}
	}
	consumed, cerr := c.storage.ConsumeMFARecoveryCode(ctx, userID, sha256Hex(normalizeRecoveryCode(code)), c.now())
	if cerr != nil {
		storageErr = cerr
	} else if consumed {
		return true, nil
	}
	if storageErr != nil && !codeMatched {
		storageErr = fmt.Errorf("%w: %w", ErrMFAVerificationUnavailable, storageErr)
	}
	return false, storageErr
}

// HasActiveMFAStepUp reports whether userID holds a current, unexpired step-up
// grant for the exact purpose given. Returns (false, nil) — not an error —
// when no matching grant exists. purpose is not optional: a grant minted for
// one purpose (e.g. restricted-secret reads) must never be read as
// authorizing a different one (e.g. an account-security-factor change).
func (c *KeyorixCore) HasActiveMFAStepUp(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose) (bool, error) {
	grant, err := c.storage.GetActiveMFAStepUpGrant(ctx, userID, purpose, c.authEffectiveNow())
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
// can never be LATER than now-retention, so a caller (originally including
// server/http/handlers/mfa_stepup_proxy.go's PruneMFAStepUpGrantsProxy,
// deleted along with the rest of the /system tier, ADR-108; server/main.go's
// store-mfa-002 scheduler is the live caller today) can only narrow the
// window, never widen it into an unbounded wipe. Returns
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
