// mfa.go — TOTP multi-factor authentication (RFC 6238): per-user opt-in
// enrolment, two-step login via a short-lived challenge, and single-use recovery
// codes. The TOTP shared secret is stored reversibly encrypted (it cannot be
// hashed); recovery and challenge tokens are SHA-256 hashed at rest.
package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// ErrMFARequired is returned by Login when the password is correct but the
// account has MFA enabled: the caller must issue a challenge (CreateMFAChallenge)
// and complete VerifyMFALogin with a one-time code.
var ErrMFARequired = errors.New("mfa required")

const (
	mfaIssuer            = "Keyorix"
	mfaRecoveryCodeCount = 10
	mfaChallengeTTL      = 5 * time.Minute
)

// BeginMFAEnrollment generates a fresh TOTP secret, stores it encrypted in a
// pending (not-activated) state, and returns the otpauth:// URI (QR) plus the
// base32 secret (manual entry). Supersedes any prior pending enrolment. Refused
// if MFA is already enabled (disable first).
func (c *KeyorixCore) BeginMFAEnrollment(ctx context.Context, userID uint) (otpauthURI, base32Secret string, err error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("user not found")
	}
	if user.MFAEnabled {
		return "", "", fmt.Errorf("MFA is already enabled; disable it first to re-enrol")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: mfaIssuer, AccountName: user.Username})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	ct, meta, err := c.encryptAuthSecret(key.Secret(), encryption.MFASecretAAD(userID))
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}
	if err := c.storage.UpsertMFASecret(ctx, &models.MFASecret{
		UserID: userID, SecretEnc: ct, SecretMeta: meta, Activated: false, CreatedAt: c.now(),
	}); err != nil {
		return "", "", fmt.Errorf("failed to store TOTP secret: %w", err)
	}
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.enrolled", &uid, nil, nil, "", fmt.Sprintf("user %s began MFA enrolment", user.Username))
	return key.URL(), key.Secret(), nil
}

// ActivateMFA verifies a TOTP code against the pending secret, enables MFA, and
// returns N single-use recovery codes (shown once).
func (c *KeyorixCore) ActivateMFA(ctx context.Context, userID uint, code string) ([]string, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	secret, err := c.loadTOTPSecret(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("no pending MFA enrolment; begin enrolment first")
	}
	if !c.validateTOTP(secret, code) {
		c.auditMFAFailed(ctx, userID, "activate")
		return nil, fmt.Errorf("invalid code")
	}
	if err := c.storage.ActivateMFASecret(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to activate MFA: %w", err)
	}
	if err := c.storage.SetUserMFAEnabled(ctx, userID, true); err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}
	// Invalidate any sessions minted before MFA was enabled (and evict them from the auth
	// cache), so a pre-enrolment session cannot outlive the security upgrade — even for
	// the cache TTL (same hygiene as password change / suspend). Best-effort: enrolment
	// must not fail on a session-cleanup error.
	_ = c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")
	codes, hashes, err := generateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if err := c.storage.CreateMFARecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("failed to store recovery codes: %w", err)
	}
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.activated", &uid, nil, nil, "", fmt.Sprintf("user %s activated MFA", user.Username))
	return codes, nil
}

// DisableMFA turns MFA off after verifying a current TOTP code OR the account
// password, then clears the secret and all recovery codes.
func (c *KeyorixCore) DisableMFA(ctx context.Context, userID uint, codeOrPassword string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled")
	}
	// Per-account lockout gates this self-service re-auth the same way it gates the
	// second login factor (VerifyMFALogin): a stolen session lets an attacker submit
	// TOTP guesses without ever having the password, so without this the code check
	// above is the ONLY throttle on disabling MFA — and it had none. Keyed by user
	// (not IP), since this is an authenticated-session endpoint, not the pre-auth
	// login path.
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	ok := false
	if secret, err := c.loadTOTPSecret(ctx, userID); err == nil && c.validateTOTP(secret, codeOrPassword) {
		ok = true
	}
	if !ok && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(codeOrPassword)) == nil {
		ok = true
	}
	if !ok {
		c.auditMFAFailed(ctx, userID, "disable")
		c.recordFailedLogin(ctx, user) // count the failed re-auth attempt toward the lockout
		return fmt.Errorf("invalid code or password")
	}
	c.clearLoginFailures(ctx, user)
	if err := c.storage.SetUserMFAEnabled(ctx, userID, false); err != nil {
		return err
	}
	if err := c.storage.DeleteMFAForUser(ctx, userID); err != nil {
		return err
	}
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.disabled", &uid, nil, nil, "", fmt.Sprintf("user %s disabled MFA", user.Username))
	return nil
}

// RegenerateMFARecoveryCodes issues a fresh set of recovery codes after verifying a
// current TOTP code OR the account password (same re-auth as DisableMFA), replacing
// any existing codes (used and unused). The plaintext codes are returned once and
// never stored. Invalidating the old set means a regenerate also revokes leaked or
// previously-recorded codes.
func (c *KeyorixCore) RegenerateMFARecoveryCodes(ctx context.Context, userID uint, codeOrPassword string) ([]string, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return nil, fmt.Errorf("MFA is not enabled")
	}
	// Same account-level lockout gate as DisableMFA (see comment there): a stolen
	// session with no lockout gating here would let an attacker brute-force the TOTP
	// code to regenerate (and so invalidate) the legitimate recovery codes.
	if c.loginLocked(user) {
		return nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	ok := false
	if secret, err := c.loadTOTPSecret(ctx, userID); err == nil && c.validateTOTP(secret, codeOrPassword) {
		ok = true
	}
	if !ok && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(codeOrPassword)) == nil {
		ok = true
	}
	if !ok {
		c.auditMFAFailed(ctx, userID, "regenerate_recovery_codes")
		c.recordFailedLogin(ctx, user) // count the failed re-auth attempt toward the lockout
		return nil, fmt.Errorf("invalid code or password")
	}
	c.clearLoginFailures(ctx, user)
	codes, hashes, err := generateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if err := c.storage.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to clear old recovery codes: %w", err)
	}
	if err := c.storage.CreateMFARecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("failed to store recovery codes: %w", err)
	}
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.recovery_codes_regenerated", &uid, nil, nil, "",
		fmt.Sprintf("user %s regenerated MFA recovery codes", user.Username))
	return codes, nil
}

// MFARecoveryCodesRemaining reports how many unused recovery codes the user has
// (and the original total), so the account UI can surface a "running low" warning.
// Returns (0, 0) when MFA is not enabled.
func (c *KeyorixCore) MFARecoveryCodesRemaining(ctx context.Context, userID uint) (remaining, total int, err error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return 0, 0, fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return 0, 0, nil
	}
	remaining, err = c.storage.CountUnusedMFARecoveryCodes(ctx, userID)
	if err != nil {
		return 0, 0, err
	}
	return remaining, mfaRecoveryCodeCount, nil
}

// CreateMFAChallenge issues a short-lived single-use challenge for an MFA-enabled
// user that has passed the password step. Only the token hash is stored.
func (c *KeyorixCore) CreateMFAChallenge(ctx context.Context, userID uint) (string, error) {
	token, err := generateSecureToken()
	if err != nil {
		return "", err
	}
	if err := c.storage.CreateMFAChallenge(ctx, &models.MFAChallenge{
		UserID: userID, TokenHash: sha256Hex(token), ExpiresAt: c.now().Add(mfaChallengeTTL), CreatedAt: c.now(),
	}); err != nil {
		return "", err
	}
	return token, nil
}

// VerifyMFALogin consumes a challenge, verifies a TOTP code or a recovery code,
// and on success mints and returns the session (the second login step).
func (c *KeyorixCore) VerifyMFALogin(ctx context.Context, challenge, code, userAgent, ip string) (*models.Session, *models.User, error) {
	ch, err := c.storage.ConsumeMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired challenge")
	}
	user, err := c.storage.GetUser(ctx, ch.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}
	// Completing a second factor still mints a login session, so a suspended or
	// deactivated account must be refused here too — the challenge may have been
	// issued (password step passed) just before an admin suspended the account, and
	// nothing rechecks the state between the two steps. Mirrors the password,
	// session, PAT, and passwordless-WebAuthn gates.
	if !user.IsActive || AccountLoginBlocked(user.AccountState) {
		return nil, nil, fmt.Errorf("account is not active")
	}
	// Per-account lockout also gates the second factor. The per-IP rate limiter is
	// spoofable behind a misconfigured proxy, and it is otherwise the ONLY online
	// throttle on TOTP/recovery-code guessing — binding failures to the account (keyed
	// by ch.UserID, which the attacker does not control) makes second-factor brute force
	// cost the same lockout as password brute force.
	if c.loginLocked(user) {
		return nil, nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	verified, usedRecovery := false, false
	if secret, err := c.loadTOTPSecret(ctx, ch.UserID); err == nil {
		if step, ok := c.validateTOTPStep(secret, code); ok {
			// Single-use within the validity window: atomically advance the last-used
			// step. A code already accepted at this (or a later) step is a replay and
			// MarkTOTPStepUsed returns false, so it is rejected — closing the ~90s
			// replay window the bare totp validation left open.
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, ch.UserID, step); ferr == nil && fresh {
				verified = true
			}
		}
	}
	if !verified {
		if consumed, err := c.storage.ConsumeMFARecoveryCode(ctx, ch.UserID, sha256Hex(normalizeRecoveryCode(code)), c.now()); err == nil && consumed {
			verified, usedRecovery = true, true
		}
	}
	if !verified {
		c.auditMFAFailed(ctx, ch.UserID, "login")
		c.recordFailedLogin(ctx, user) // count the failed second factor toward the lockout
		return nil, nil, fmt.Errorf("invalid code")
	}
	// Cleared the second factor — reset any lockout state accrued from failed codes.
	c.clearLoginFailures(ctx, user)
	session, err := c.mintSession(ctx, ch.UserID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	uid := ch.UserID
	if usedRecovery {
		c.writeAuditEventFull(ctx, "mfa.recovery_used", &uid, nil, nil, ip, fmt.Sprintf("user %s used a recovery code", user.Username))
	}
	c.writeAuditEventFull(ctx, "mfa.login_verified", &uid, nil, nil, ip, fmt.Sprintf("user %s passed MFA", user.Username))
	return session, user, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func (c *KeyorixCore) loadTOTPSecret(ctx context.Context, userID uint) (string, error) {
	row, err := c.storage.GetMFASecret(ctx, userID)
	if err != nil {
		return "", err
	}
	return c.decryptAuthSecret(row.SecretEnc, row.SecretMeta, encryption.MFASecretAAD(userID))
}

func (c *KeyorixCore) validateTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	// ±1 time-step skew (clock drift); standard 30s SHA-1 6-digit TOTP.
	valid, _ := totp.ValidateCustom(code, secret, c.now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

// totpPeriod is the TOTP step length in seconds.
const totpPeriod = 30

// validateTOTPStep verifies code against the current step and ±1 skew and, on a match,
// returns the matched time-step (unix/period) so the caller can enforce single-use
// (anti-replay). Unlike validateTOTP it identifies WHICH step matched.
func (c *KeyorixCore) validateTOTPStep(secret, code string) (int64, bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, false
	}
	now := c.now().UTC()
	for _, delta := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(delta*totpPeriod) * time.Second)
		expected, err := totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{
			Period: totpPeriod, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return t.Unix() / totpPeriod, true
		}
	}
	return 0, false
}

func (c *KeyorixCore) auditMFAFailed(ctx context.Context, userID uint, phase string) {
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.failed", &uid, nil, nil, "", fmt.Sprintf("failed MFA %s for user %d", phase, userID))
}

// generateRecoveryCodes returns n human-friendly codes and their SHA-256 hashes.
func generateRecoveryCodes(n int) (codes, hashes []string, err error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous 0/O/1/I
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for j, x := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, sha256Hex(normalizeRecoveryCode(code)))
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode makes entry forgiving: upper-cased, dash/space-stripped.
func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}
