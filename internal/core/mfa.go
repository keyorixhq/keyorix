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
// if MFA is already enabled (disable first), or if at-rest encryption is
// unavailable (see the authEncryptor check below).
func (c *KeyorixCore) BeginMFAEnrollment(ctx context.Context, userID uint) (otpauthURI, base32Secret string, err error) {
	// The TOTP secret is a distinct, always-sensitive credential — unlike a general
	// secret VALUE (whose at-rest encryption is an explicit, informed operator
	// trade-off when disabled), a user enrolling MFA has no visibility into or
	// control over the server's encryption setting. Silently falling back to
	// encryptAuthSecret's plaintext passthrough would store the TOTP seed in the
	// clear with no signal to anyone. Fail closed instead, mirroring how this
	// codebase treats other capabilities that need encryption (audit-checkpoint
	// signing, evidence signing): "unavailable" when encryption is off, not
	// silently weaker.
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return "", "", fmt.Errorf("MFA enrolment requires at-rest encryption to be enabled (the TOTP secret must not be stored in plaintext); ask an administrator to enable encryption")
	}
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
// returns N single-use recovery codes (shown once). password re-authenticates the
// caller (#372): code alone is NOT sufficient proof of the account holder here,
// because it is checked against the PENDING secret that BeginMFAEnrollment just
// generated — an attacker with a stolen session or PAT can call BeginMFAEnrollment
// themselves and so always knows a "valid" code for it. Unlike DisableMFA/
// RegenerateMFARecoveryCodes (which re-authenticate against an already-ACTIVE
// factor and so accept a current TOTP code OR the password), activation happens
// before MFA is enabled, so there is no pre-existing TOTP factor to check against —
// the password is the only trustworthy re-proof available at this step.
func (c *KeyorixCore) ActivateMFA(ctx context.Context, userID uint, code, password string) ([]string, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if err := c.requireReauth(ctx, user, password, "activate_reauth"); err != nil {
		return nil, err
	}
	secret, err := c.loadTOTPSecret(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("no pending MFA enrolment; begin enrolment first")
	}
	step, ok := c.validateTOTPStep(secret, code)
	if !ok {
		c.auditMFAFailed(ctx, userID, "activate")
		return nil, fmt.Errorf("invalid code")
	}
	if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, userID, step); ferr != nil || !fresh {
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
	if err := c.requireReauth(ctx, user, codeOrPassword, "disable"); err != nil {
		return err
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
	if err := c.requireReauth(ctx, user, codeOrPassword, "regenerate_recovery_codes"); err != nil {
		return nil, err
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

// RemoteMFAVerifier is implemented by storage backends that cannot themselves
// hold the raw TOTP secret (#509), for the identical reason RemoteLoginVerifier
// (auth.go) exists for passwords: the shared secret is stored reversibly
// ENCRYPTED specifically so it must never leave the server that can decrypt it,
// so RemoteStorage's GetMFASecret is an unconditional stub — loadTOTPSecret/
// validateTOTPStep can never run locally against a "spoke" server backed by
// RemoteStorage.
//
// Mirrors #506's proxy-login pattern exactly, extended to the second factor:
// the upstream server (the one actually backed by LocalStorage, which HAS the
// encrypted secret and the key to decrypt it) performs BOTH steps —
//
//  1. IssueMFAChallenge mints the short-lived, single-use challenge (the same
//     shape CreateMFAChallenge always minted, just persisted upstream instead
//     of locally) via POST /api/v1/users/{id}/mfa-challenge.
//  2. VerifyMFALoginCredentials consumes that challenge and performs the ENTIRE
//     TOTP/recovery-code check — validateTOTPStep, MarkTOTPStepUsed (anti-
//     replay), ConsumeMFARecoveryCode, AND the per-account lockout gate/
//     accounting and account-active/account-state checks (the exact set
//     VerifyPasswordCredentials's proxy already delegates for the first
//     factor) — via POST /api/v1/users/verify-mfa, calling the upstream's own
//     core.VerifyMFACredentials, the SAME function the upstream's own direct
//     second-factor login uses, not a parallel reimplementation.
//
// Both endpoints are gated by the SAME users.write permission CreateUser/
// UnlockUser/verify-credentials already require of the RemoteStorage service
// credential — not a new, weaker trust boundary. Minting a challenge here is
// specifically NOT the privilege-escalation oracle #508 identified for a
// generic "create a session for this user_id" primitive (deliberately NOT
// implemented for that reason): a challenge alone grants nothing by itself —
// the caller must still supply the correct plaintext TOTP code or recovery
// code, throttled by the identical per-account lockout #506 already proxies —
// so at most it lets this already-highly-trusted credential skip re-proving a
// password it (or rather, the legitimate #506 proxy call preceding this one)
// already proved once, exactly as CreateUser/UnlockUser already let it act on
// an arbitrary account without a fresh password check.
type RemoteMFAVerifier interface {
	IssueMFAChallenge(ctx context.Context, userID uint) (string, error)
	VerifyMFALoginCredentials(ctx context.Context, challenge, code string) (*models.User, bool, error)
}

// CreateMFAChallenge issues a short-lived single-use challenge for an MFA-enabled
// user that has passed the password step. Only the token hash is stored.
func (c *KeyorixCore) CreateMFAChallenge(ctx context.Context, userID uint) (string, error) {
	if verifier, ok := c.storage.(RemoteMFAVerifier); ok {
		return verifier.IssueMFAChallenge(ctx, userID)
	}
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

// VerifyMFACredentials consumes a challenge and verifies a TOTP code or a
// recovery code against LocalStorage — everything VerifyMFALogin does EXCEPT
// minting the session and the two post-mint audit writes, extracted (#509) so
// it can ALSO be called directly by the server-side handler for POST
// /api/v1/users/verify-mfa, the upstream half of the RemoteMFAVerifier proxy
// (see its doc above) — the identical split #506 already established between
// VerifyPasswordCredentials (the shared check) and Login (which additionally
// mints the session). This keeps the direct LocalStorage second-factor login
// and the proxied storage.type: remote path running through IDENTICAL TOTP/
// recovery-code/lockout/account-state logic — never two, potentially-
// diverging implementations of the same security check. Returns the verified
// user (ID and Username only are guaranteed populated — see
// verifyMFAWireResponse in internal/storage/store for why nothing else is
// needed past this point) and whether a recovery code (rather than a TOTP
// code) was used.
func (c *KeyorixCore) VerifyMFACredentials(ctx context.Context, challenge, code string) (*models.User, bool, error) { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	ch, err := c.storage.ConsumeMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		return nil, false, fmt.Errorf("invalid or expired challenge")
	}
	user, err := c.storage.GetUser(ctx, ch.UserID)
	if err != nil {
		return nil, false, fmt.Errorf("user not found")
	}
	// Completing a second factor still mints a login session, so a suspended or
	// deactivated account must be refused here too — the challenge may have been
	// issued (password step passed) just before an admin suspended the account, and
	// nothing rechecks the state between the two steps. Mirrors the password,
	// session, PAT, and passwordless-WebAuthn gates.
	if !user.IsActive || AccountLoginBlocked(user.AccountState) {
		return nil, false, fmt.Errorf("account is not active")
	}
	// Per-account lockout also gates the second factor. The per-IP rate limiter is
	// spoofable behind a misconfigured proxy, and it is otherwise the ONLY online
	// throttle on TOTP/recovery-code guessing — binding failures to the account (keyed
	// by ch.UserID, which the attacker does not control) makes second-factor brute force
	// cost the same lockout as password brute force.
	if c.loginLocked(user) {
		return nil, false, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
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
		return nil, false, fmt.Errorf("invalid code")
	}
	// Cleared the second factor — but a concurrent burst of failed second-factor
	// attempts against this account may have tripped the lock since the
	// pre-verification snapshot check above (TOCTOU). Re-check under the same
	// serialization recordFailedLogin uses before minting a session.
	if err := c.checkLockAndClearLoginFailures(ctx, user); err != nil {
		return nil, false, err
	}
	return user, usedRecovery, nil
}

// VerifyMFALogin consumes a challenge, verifies a TOTP code or a recovery code,
// and on success mints and returns the session (the second login step).
func (c *KeyorixCore) VerifyMFALogin(ctx context.Context, challenge, code, userAgent, ip string) (*models.Session, *models.User, error) {
	var user *models.User
	var usedRecovery bool
	var err error
	if verifier, ok := c.storage.(RemoteMFAVerifier); ok {
		user, usedRecovery, err = verifier.VerifyMFALoginCredentials(ctx, challenge, code)
	} else {
		user, usedRecovery, err = c.VerifyMFACredentials(ctx, challenge, code)
	}
	if err != nil {
		return nil, nil, err
	}
	// Apply the same password-expiry hard gate as the non-MFA login path (ADR-025).
	// Idempotent: the gate is a no-op when the state is already password_reset_required
	// (set during the initial credential check for MFA-enabled accounts).
	if err := c.enforcePasswordExpiryGate(ctx, user); err != nil {
		return nil, nil, err
	}
	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	// Record the MFA step-up window when the classification gate requires it.
	// Best-effort: a write failure does not block the login, but the user won't
	// be able to read restricted secrets until they re-verify successfully.
	if c.classificationRestrictedRequiresMFAStepUp {
		_ = c.storage.UpsertMFAStepupToken(ctx, user.ID, c.now().Add(c.mfaStepUpWindow()))
	}
	uid := user.ID
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

// requireReauth is the shared self-service re-authentication gate (#372) for
// account-security-factor changes: it verifies codeOrPassword against a CURRENT,
// already-active TOTP secret (only when user.MFAEnabled — never against an
// in-flight, not-yet-activated enrolment secret, which an attacker who just called
// BeginMFAEnrollment/BeginWebAuthnRegistration themselves would already know) or
// the account password. Every caller (DisableMFA, RegenerateMFARecoveryCodes,
// ActivateMFA, FinishWebAuthnRegistration, DeleteWebAuthnCredential) is reachable
// with nothing but a bearer token — a stolen session OR a narrowly-scoped PAT,
// which ADR-042 exempts from MFA policy entirely — so this check is the only thing
// standing between a leaked bearer and a full account-security-factor takeover.
// Feeds the same per-account lockout the second login factor (VerifyMFALogin)
// uses, keyed by user (not IP, since this is an authenticated-session endpoint):
// without it, this check would be the only throttle on guessing. phase labels the
// mfa.failed audit event on a failed attempt.
func (c *KeyorixCore) requireReauth(ctx context.Context, user *models.User, codeOrPassword, phase string) error {
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	ok := false
	if user.MFAEnabled {
		if secret, err := c.loadTOTPSecret(ctx, user.ID); err == nil {
			// Use the same anti-replay path as VerifyMFACredentials: identify the
			// matched time-step and atomically mark it used so a stolen code cannot
			// be replayed within the ±1 step (~90 s) window.
			if step, matched := c.validateTOTPStep(secret, codeOrPassword); matched {
				if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, user.ID, step); ferr == nil && fresh {
					ok = true
				}
			}
		}
	}
	if !ok && codeOrPassword != "" && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(codeOrPassword)) == nil {
		ok = true
	}
	if !ok {
		c.auditMFAFailed(ctx, user.ID, phase)
		c.recordFailedLogin(ctx, user) // count the failed re-auth attempt toward the lockout
		return fmt.Errorf("invalid code or password")
	}
	c.clearLoginFailures(ctx, user)
	return nil
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
