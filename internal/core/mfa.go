// mfa.go — TOTP multi-factor authentication (RFC 6238): per-user opt-in
// enrolment, two-step login via a short-lived challenge, and single-use recovery
// codes. The TOTP shared secret is stored reversibly encrypted (it cannot be
// hashed); recovery and challenge tokens are SHA-256 hashed at rest.
package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

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
	ct, meta, err := c.encryptAuthSecret(key.Secret())
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
	// Invalidate any sessions minted before MFA was enabled, so a pre-enrolment
	// session cannot outlive the security upgrade (same hygiene as password change
	// / suspend). Best-effort: enrolment must not fail on a session-cleanup error.
	_ = c.storage.DeleteSessionsForUserExcept(ctx, userID, 0)
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
	ok := false
	if secret, err := c.loadTOTPSecret(ctx, userID); err == nil && c.validateTOTP(secret, codeOrPassword) {
		ok = true
	}
	if !ok && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(codeOrPassword)) == nil {
		ok = true
	}
	if !ok {
		c.auditMFAFailed(ctx, userID, "disable")
		return fmt.Errorf("invalid code or password")
	}
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
	ok := false
	if secret, err := c.loadTOTPSecret(ctx, userID); err == nil && c.validateTOTP(secret, codeOrPassword) {
		ok = true
	}
	if !ok && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(codeOrPassword)) == nil {
		ok = true
	}
	if !ok {
		c.auditMFAFailed(ctx, userID, "regenerate_recovery_codes")
		return nil, fmt.Errorf("invalid code or password")
	}
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
	verified, usedRecovery := false, false
	if secret, err := c.loadTOTPSecret(ctx, ch.UserID); err == nil && c.validateTOTP(secret, code) {
		verified = true
	} else if consumed, err := c.storage.ConsumeMFARecoveryCode(ctx, ch.UserID, sha256Hex(normalizeRecoveryCode(code)), c.now()); err == nil && consumed {
		verified, usedRecovery = true, true
	}
	if !verified {
		c.auditMFAFailed(ctx, ch.UserID, "login")
		return nil, nil, fmt.Errorf("invalid code")
	}
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
	return c.decryptAuthSecret(row.SecretEnc, row.SecretMeta)
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
