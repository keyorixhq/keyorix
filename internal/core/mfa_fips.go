package core

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
)

// ErrTOTPUnavailableInFIPSMode is returned, unwrapped or wrapped, when a TOTP
// operation is refused because the process runs with Go's FIPS 140-only mode
// enforced (GODEBUG=fips140=only). Keyorix TOTP is HMAC-SHA-1 (RFC 6238, the
// algorithm every authenticator app defaults to), and the Go FIPS module panics
// on SHA-1 HMAC in that mode. The refusal happens BEFORE any code is evaluated:
// nothing is consumed, nothing is counted toward the lockout, and the answer
// says nothing about whether the submitted code was right. Recovery codes
// (SHA-256) and passkeys are unaffected. Whether FIPS mode should offer TOTP
// with another algorithm or refuse it outright is an open product decision;
// this is only the no-panic step. Handlers map it to a 503 with this text.
var ErrTOTPUnavailableInFIPSMode = errors.New("TOTP is not available in FIPS mode")

// totpFIPSEnforced reports whether TOTP must be refused. A variable so the
// default-mode tests can exercise the refusal paths; production never changes it.
var totpFIPSEnforced = fips140.Enforced

// totpUnavailable returns ErrTOTPUnavailableInFIPSMode when TOTP is refused, nil
// otherwise.
func totpUnavailable() error {
	if totpFIPSEnforced() {
		return ErrTOTPUnavailableInFIPSMode
	}
	return nil
}

// auditTOTPUnavailable records the refusal as mfa.error: no code was evaluated,
// so it must not read like a failed attempt (mfa.failed).
func (c *KeyorixCore) auditTOTPUnavailable(ctx context.Context, userID uint, phase string) {
	uid := userID
	c.writeAuditEventFailedFull(ctx, "mfa.error", &uid, nil, nil, "",
		fmt.Sprintf("MFA %s for user %d refused without evaluating the code: %v", phase, userID, ErrTOTPUnavailableInFIPSMode))
}

// totpUnavailablePreVerdict is the error the second-factor verifiers return for
// a TOTP-shaped code under FIPS enforcement. ErrMFAVerificationUnavailable is
// the existing "no code was evaluated" signal: the handlers hand the login
// budget slot back for it and core does not count it, which is correct because
// nothing was checked, so the refusal cannot be used to guess.
func totpUnavailablePreVerdict() error {
	return fmt.Errorf("%w: %w", ErrMFAVerificationUnavailable, ErrTOTPUnavailableInFIPSMode)
}
