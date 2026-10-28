// mfa_reset_effect.go — what an administrator MFA reset does to the target account
// (RECOVERY-MFA-RESET-1, docs/design/recovery-options.md §1). One definition,
// shared by the host command (`keyorix-server admin reset-mfa`, server/admin) and
// the online two-admin reset (ApproveMFAReset), so the two can never drift into
// different notions of "reset".
//
// A reset is a full credential reset, never "MFA off": clearing the second factor
// and leaving the password would turn a stolen password, the threat MFA exists
// for, into a takeover. So the same transaction also replaces the password with a
// one-time password and ends every session and PAT.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventMFAReset audits (and types the notification of) a completed online MFA
// reset; the host command writes admin.reset_mfa instead.
const EventMFAReset = "mfa.reset"

// MFAResetEffect counts what ResetMFACredentialsInTx removed. Counts only: no
// secret, code, credential id or token ever leaves the function.
type MFAResetEffect struct {
	TOTPCleared                bool
	RecoveryCodesCleared       int
	WebAuthnCredentialsCleared int
	SessionsRevoked            int
	PATsRevoked                int
	// EvictHashes are the session and PAT token hashes the caller evicts from the
	// HTTP auth cache AFTER the transaction commits (never before: a rolled-back
	// reset must not evict a still-valid entry). Not for logging.
	EvictHashes []string
}

// Summary is the audit/notification wording of the effect.
func (e *MFAResetEffect) Summary() string {
	totp := "no TOTP factor"
	if e.TOTPCleared {
		totp = "TOTP factor removed"
	}
	return fmt.Sprintf("%s, %d unused recovery code(s) removed, %d WebAuthn credential(s) removed, %d session(s) and %d personal access token(s) revoked, password replaced by a one-time password, a new MFA enrolment is required",
		totp, e.RecoveryCodesCleared, e.WebAuthnCredentialsCleared, e.SessionsRevoked, e.PATsRevoked)
}

// ResetMFACredentialsInTx applies the reset to target inside tx. The caller owns:
// locking and re-validating the target row in the same transaction (target is that
// locked row), generating otpHash, writing the audit row in the same transaction
// (the reset is fail closed on it), and evicting EvictHashes after commit.
//
// In order: every session deleted and every PAT revoked; the TOTP secret, the
// recovery codes, every WebAuthn credential and every step-up grant removed; the
// account put in the restricted password_reset_required state (which every binary
// confines to a password change) with the one-time password and its expiry; the
// login lockout cleared; users.mfa_enrolment_required set. Any error aborts the
// whole transaction: nothing is half-reset.
func ResetMFACredentialsInTx(ctx context.Context, tx storage.Storage, target *models.User, otpHash string, otpExpiresAt, now time.Time) (*MFAResetEffect, error) {
	if target == nil || target.ID == 0 || otpHash == "" {
		return nil, fmt.Errorf("MFA reset: target and one-time password are required")
	}
	uid := target.ID
	eff := &MFAResetEffect{TOTPCleared: target.MFAEnabled}

	sessions, err := tx.ListSessionTokenHashesForUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	if err := tx.DeleteSessionsForUserExcept(ctx, uid, 0); err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}
	eff.SessionsRevoked = len(sessions)
	pats, err := tx.RevokeAllPersonalAccessTokensForUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("revoke personal access tokens: %w", err)
	}
	eff.PATsRevoked = len(pats)
	eff.EvictHashes = append(append(eff.EvictHashes, sessions...), pats...)

	if eff.RecoveryCodesCleared, err = tx.CountUnusedMFARecoveryCodes(ctx, uid); err != nil {
		return nil, fmt.Errorf("count recovery codes: %w", err)
	}
	if err := tx.SetUserMFAEnabled(ctx, uid, false); err != nil {
		return nil, fmt.Errorf("clear MFA flag: %w", err)
	}
	if err := tx.DeleteMFAForUser(ctx, uid); err != nil {
		return nil, fmt.Errorf("remove TOTP secret and recovery codes: %w", err)
	}
	creds, err := tx.ListWebAuthnCredentials(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("list WebAuthn credentials: %w", err)
	}
	for _, c := range creds {
		if err := tx.DeleteWebAuthnCredential(ctx, uid, c.ID); err != nil {
			return nil, fmt.Errorf("remove WebAuthn credential: %w", err)
		}
	}
	eff.WebAuthnCredentialsCleared = len(creds)
	// The flag too, not only the rows: a WebAuthnEnabled account with no
	// credential would be asked for a passkey it no longer has.
	if err := tx.SetUserWebAuthnEnabled(ctx, uid, false); err != nil {
		return nil, fmt.Errorf("clear WebAuthn flag: %w", err)
	}
	if err := tx.DeleteMFAStepUpGrantsFor(ctx, uid); err != nil {
		return nil, fmt.Errorf("remove step-up grants: %w", err)
	}

	if err := tx.SetAccountState(ctx, uid, AccountPasswordResetRequired, now); err != nil {
		return nil, fmt.Errorf("restrict account: %w", err)
	}
	if err := tx.SetPasswordHash(ctx, uid, otpHash, now); err != nil {
		return nil, fmt.Errorf("set one-time password: %w", err)
	}
	// After SetPasswordHash, which clears any earlier expiry: the one-time
	// password never exists without its expiry (OTP-EXPIRY-1).
	exp := otpExpiresAt.UTC()
	if err := tx.SetOneTimePasswordExpiry(ctx, uid, &exp, now); err != nil {
		return nil, fmt.Errorf("set one-time password expiry: %w", err)
	}
	if err := tx.UpdateLoginLockoutState(ctx, uid, 0, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("clear login lockout: %w", err)
	}
	if err := tx.SetUserMFAEnrolmentRequired(ctx, uid, true); err != nil {
		return nil, fmt.Errorf("require MFA enrolment: %w", err)
	}
	return eff, nil
}

// MFAEnrolmentOwed reports whether u still owes the enrolment an administrator MFA
// reset demands: the flag is set and no factor has been enrolled since.
func MFAEnrolmentOwed(u *models.User) bool {
	return u != nil && u.MFAEnrolmentRequired && !userHasSecondFactor(u)
}
