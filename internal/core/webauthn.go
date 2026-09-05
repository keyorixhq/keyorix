// webauthn.go — WebAuthn / passkeys (ADR-036): a phishing-resistant second
// factor. Self-service registration of FIDO2 authenticators, and a two-step login
// where a WebAuthn assertion (instead of, or in addition to, TOTP) completes the
// pre-auth challenge minted by the password step. The in-flight ceremony state
// (challenge etc.) is persisted single-use and hashed at rest, like MFAChallenge.
package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrWebAuthnDisabled is returned when a WebAuthn operation is attempted but the
// server has no relying party configured (no webauthn block in the config).
var ErrWebAuthnDisabled = errors.New("webauthn is not enabled on this server")

const webauthnSessionTTL = 5 * time.Minute

// EventWebAuthnCloneDetected is the loud, authentication-rejecting audit event
// fired when go-webauthn's signature-counter clone-detection signal
// (Authenticator.CloneWarning) fires (#212). The library itself already excludes
// the one legitimate always-zero-counter case (see its UpdateCounter: both the
// stored and asserted counts must be zero for the warning to be waived), so any
// warning reaching here is a genuine regression, not a benign authenticator that
// never implemented a counter.
const EventWebAuthnCloneDetected = "webauthn.clone_detected" // #nosec G101 -- audit event type, not a credential

// NotificationWebAuthnCloneDetected is the in-app/email notification type sent to
// the affected account owner alongside EventWebAuthnCloneDetected.
const NotificationWebAuthnCloneDetected = EventWebAuthnCloneDetected

// webauthnUser adapts a Keyorix user + its stored credentials to the
// webauthn.User interface the library expects.
type webauthnUser struct {
	user  *models.User
	creds []webauthn.Credential
}

// WebAuthnID is the stable user handle (8-byte big-endian user ID). It must not
// contain PII (it is stored on the authenticator), so we use the opaque ID.
func (u *webauthnUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.user.ID))
	return b
}
func (u *webauthnUser) WebAuthnName() string                       { return u.user.Username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (c *KeyorixCore) loadWebAuthnUser(ctx context.Context, userID uint) (*webauthnUser, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	rows, err := c.storage.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		if r.Disabled {
			// Flagged by clone-detection (#212, signature-counter regression) —
			// excluded from every ceremony (login candidate set AND registration
			// exclusion list) until the owner deletes it and registers a fresh
			// passkey using the genuine physical authenticator.
			continue
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(r.CredentialBlob, &cred); err != nil {
			continue // skip an unreadable row rather than fail the whole ceremony
		}
		creds = append(creds, cred)
	}
	return &webauthnUser{user: user, creds: creds}, nil
}

// storeWebAuthnSession persists the ceremony SessionData under the hash of an
// opaque token (returned to the caller), single-use and short-lived.
func (c *KeyorixCore) storeWebAuthnSession(ctx context.Context, userID uint, purpose string, sd *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	token, err := generateSecureToken()
	if err != nil {
		return "", err
	}
	if err := c.storage.CreateWebAuthnSession(ctx, &models.WebAuthnSession{
		UserID:    userID,
		TokenHash: sha256Hex(token),
		Purpose:   purpose,
		Data:      data,
		ExpiresAt: c.now().Add(webauthnSessionTTL),
		CreatedAt: c.now(),
	}); err != nil {
		return "", err
	}
	return token, nil
}

// BeginWebAuthnRegistration starts enrolment of a new passkey for the caller. It
// returns the CredentialCreation options (for navigator.credentials.create) and
// an opaque session token to echo back at FinishWebAuthnRegistration.
func (c *KeyorixCore) BeginWebAuthnRegistration(ctx context.Context, userID uint) (*protocol.CredentialCreation, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	wu, err := c.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	// Exclude already-registered authenticators so the user can't double-register one.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for i := range wu.creds {
		exclusions = append(exclusions, wu.creds[i].Descriptor())
	}
	// Request a discoverable (resident) credential so the passkey can also be used
	// for passwordless login (ADR-036 addendum). "preferred" is backward-compatible:
	// authenticators that can't store a resident key still register for the
	// second-factor flow.
	creation, sd, err := c.webauthnRP.BeginRegistration(wu,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}
	token, err := c.storeWebAuthnSession(ctx, userID, "register", sd)
	if err != nil {
		return nil, "", err
	}
	return creation, token, nil
}

// FinishWebAuthnRegistration verifies the attestation, stores the credential, and
// enables WebAuthn for the user. name is a user-supplied label for the passkey.
// codeOrPassword re-authenticates the caller (#372): a current TOTP code (if MFA
// is already enabled) or the account password, same re-auth as DisableMFA. This
// is the step that actually adds a new, attacker-controllable trust factor to the
// account, so — unlike BeginWebAuthnRegistration, which only opens a ceremony with
// no effect on stored credentials — it must not be reachable by a bearer token
// alone (a stolen session or a scoped, MFA-policy-exempt PAT per ADR-042).
func (c *KeyorixCore) FinishWebAuthnRegistration(ctx context.Context, userID uint, sessionToken, name, codeOrPassword string, parsed *protocol.ParsedCredentialCreationData) (*models.WebAuthnCredential, error) {
	if c.webauthnRP == nil {
		return nil, ErrWebAuthnDisabled
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if err := c.requireReauth(ctx, user, codeOrPassword, "webauthn_register"); err != nil {
		return nil, err
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		return nil, fmt.Errorf("invalid or expired registration session")
	}
	if sess.Purpose != "register" || sess.UserID != userID {
		return nil, fmt.Errorf("registration session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return nil, err
	}
	wu, err := c.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	cred, err := c.webauthnRP.CreateCredential(wu, sd, parsed)
	if err != nil {
		c.auditWebAuthnFailed(ctx, userID, "register")
		return nil, fmt.Errorf("failed to verify attestation: %w", err)
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	row := &models.WebAuthnCredential{
		UserID:         userID,
		CredentialID:   cred.ID,
		Name:           name,
		CredentialBlob: blob,
		CreatedAt:      c.now(),
	}
	if err := c.storage.CreateWebAuthnCredential(ctx, row); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}
	// On the first passkey, enable WebAuthn and purge any pre-enrolment sessions so
	// a session minted before the security upgrade cannot outlive it (same hygiene
	// as MFA activation).
	firstEnrol := !wu.user.WebAuthnEnabled
	if err := c.storage.SetUserWebAuthnEnabled(ctx, userID, true); err != nil {
		return nil, err
	}
	if firstEnrol {
		// Purge pre-enrolment sessions AND evict them from the auth cache, so a session
		// minted before the security upgrade cannot outlive it even for the cache TTL.
		_ = c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")
	}
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.registered", &uid, nil, nil, "",
		fmt.Sprintf("user %s registered passkey %q", wu.user.Username, name))
	return row, nil
}

// ListWebAuthnCredentials returns the caller's registered passkeys.
func (c *KeyorixCore) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	return c.storage.ListWebAuthnCredentials(ctx, userID)
}

// DeleteWebAuthnCredential removes one of the caller's passkeys; if it was the
// last one, WebAuthn is disabled for the account. codeOrPassword re-authenticates
// the caller (#372, same re-auth as DisableMFA): deleting every passkey silently
// disables WebAuthn account-wide, a full second-factor downgrade that must not be
// reachable by a bearer token alone (a stolen session or a scoped, MFA-policy-
// exempt PAT per ADR-042).
func (c *KeyorixCore) DeleteWebAuthnCredential(ctx context.Context, userID, id uint, codeOrPassword string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if err := c.requireReauth(ctx, user, codeOrPassword, "webauthn_delete"); err != nil {
		return err
	}
	if err := c.storage.DeleteWebAuthnCredential(ctx, userID, id); err != nil {
		return err
	}
	n, err := c.storage.CountWebAuthnCredentials(ctx, userID)
	if err != nil {
		return err
	}
	if n == 0 {
		if err := c.storage.SetUserWebAuthnEnabled(ctx, userID, false); err != nil {
			return err
		}
		// Last passkey removed — security downgrade. Purge all sessions so a session
		// minted under WebAuthn enforcement cannot outlive the second-factor removal,
		// symmetric with FinishWebAuthnRegistration's session purge on first enrolment.
		_ = c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")
	}
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.credential_removed", &uid, nil, nil, "",
		fmt.Sprintf("user %d removed a passkey (%d remaining)", userID, n))
	return nil
}

// BeginWebAuthnLogin starts the assertion ceremony for the second login step. It
// resolves the user from the (still-unconsumed) MFA challenge minted by the
// password step, and returns the CredentialAssertion options plus an opaque
// webauthn session token to echo back at FinishWebAuthnLogin (alongside the
// challenge, which is consumed there).
func (c *KeyorixCore) BeginWebAuthnLogin(ctx context.Context, challenge string) (*protocol.CredentialAssertion, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	ch, err := c.storage.GetActiveMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		return nil, "", fmt.Errorf("invalid or expired challenge")
	}
	wu, err := c.loadWebAuthnUser(ctx, ch.UserID)
	if err != nil {
		return nil, "", err
	}
	if len(wu.creds) == 0 {
		return nil, "", fmt.Errorf("no passkeys registered")
	}
	// WAUN-001: require user-verification (PIN or biometric) for the MFA assertion,
	// not just key presence — prevents a stolen/found hardware key from satisfying the
	// second factor without the user's knowledge.
	assertion, sd, err := c.webauthnRP.BeginLogin(wu,
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin login: %w", err)
	}
	token, err := c.storeWebAuthnSession(ctx, ch.UserID, "login", sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// checkWebAuthnAccountGates refuses a WebAuthn second-factor login when the account
// is blocked (suspended/deactivated) or locked out, mirroring the TOTP path in
// VerifyMFALogin and the passwordless path below.
func (c *KeyorixCore) checkWebAuthnAccountGates(wu *webauthnUser) error {
	if !wu.user.IsActive || AccountLoginBlocked(wu.user.ID, wu.user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	// Per-IP limiters are spoofable behind a proxy; bind assertion failures to the
	// account instead. ch.UserID is password-gated so this cannot lock an arbitrary victim.
	if c.loginLocked(wu.user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	return nil
}

// FinishWebAuthnLogin consumes the challenge + webauthn session, verifies the
// assertion, updates the credential's signature counter, and mints the session.
func (c *KeyorixCore) FinishWebAuthnLogin(ctx context.Context, challenge, sessionToken, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData) (*models.Session, *models.User, error) {
	if c.webauthnRP == nil {
		return nil, nil, ErrWebAuthnDisabled
	}
	// Consume the challenge first — it is the single-use login gate.
	ch, err := c.storage.ConsumeMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired challenge")
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired webauthn session")
	}
	if sess.Purpose != "login" || sess.UserID != ch.UserID {
		return nil, nil, fmt.Errorf("webauthn session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return nil, nil, err
	}
	wu, err := c.loadWebAuthnUser(ctx, ch.UserID)
	if err != nil {
		return nil, nil, err
	}
	// A second-factor WebAuthn login still mints a session, so a suspended or
	// deactivated account must be refused — the challenge may have been issued just
	// before suspension, with nothing rechecking state between steps. Mirrors the
	// passwordless path's AccountLoginBlocked gate (and the password/session gates).
	// Per-account lockout also gates the second factor (parity with VerifyMFALogin).
	if err := c.checkWebAuthnAccountGates(wu); err != nil {
		return nil, nil, err
	}
	cred, err := c.webauthnRP.ValidateLogin(wu, sd, parsed)
	if err != nil {
		c.auditWebAuthnFailed(ctx, ch.UserID, "login")
		c.recordFailedLogin(ctx, wu.user) // count the failed second factor toward the lockout
		return nil, nil, fmt.Errorf("assertion verification failed: %w", err)
	}
	// Clone-detection (#212): a signature-counter regression is a stronger, more
	// specific signal than a simple bad assertion, so it is checked and refused
	// FIRST — before the login is otherwise treated as successful in any way,
	// including clearing the lockout counters below — no session is minted, the
	// credential is disabled, and the owner is alerted (see rejectIfCloned).
	if err := c.rejectIfCloned(ctx, ch.UserID, cred, ip); err != nil {
		return nil, nil, err
	}
	// A concurrent burst of failed second-factor attempts against this account may
	// have tripped the lock since the pre-verification snapshot check above
	// (TOCTOU). Re-check under the same serialization recordFailedLogin uses
	// before minting a session; on success this also clears the lockout counters,
	// superseding a bare clearLoginFailures call.
	if err := c.checkLockAndClearLoginFailures(ctx, wu.user); err != nil {
		return nil, nil, err
	}
	c.persistUpdatedCredential(ctx, ch.UserID, cred)

	if err := c.enforcePasswordExpiryGate(ctx, wu.user); err != nil {
		return nil, nil, err
	}
	session, err := c.mintSession(ctx, ch.UserID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	// Record the MFA step-up window when the classification gate requires it,
	// matching the existing TOTP path in VerifyMFALogin. WebAuthn (possession +
	// user-verification) is at least as strong as TOTP, so it must satisfy the
	// same restricted_requires_mfa_stepup gate. Best-effort: a write failure
	// does not block the login.
	if c.classificationRestrictedRequiresMFAStepUp {
		_ = c.storage.UpsertMFAStepupToken(ctx, ch.UserID, c.now().Add(c.mfaStepUpWindow()))
	}
	// Also mint a genuine MFAStepUpGrant, unconditionally (not gated behind
	// classificationRestrictedRequiresMFAStepUp): a WebAuthn login is itself proof
	// of possessing the second factor, but — unlike TOTP, which requireReauth can
	// verify directly against a freshly-typed code — a passkey assertion has no
	// typable "code" to hand a later self-service re-auth call. Without this,
	// requireReauth's second-factor requirement (#372-follow-up) would have no
	// path at all for a WebAuthn-only account. Best-effort: a write failure does
	// not block the login.
	_ = c.storage.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ch.UserID, ExpiresAt: c.now().Add(c.mfaStepUpWindow())})
	uid := ch.UserID
	c.writeAuditEventFull(ctx, "webauthn.login_verified", &uid, nil, nil, ip,
		fmt.Sprintf("user %s passed WebAuthn", wu.user.Username))
	return session, wu.user, nil
}

// BeginWebAuthnPasswordlessLogin starts a discoverable (usernameless) login. No
// user is identified yet — the authenticator reveals which resident passkey (and
// thus which user) to use. User verification is REQUIRED, so the single passkey
// gesture proves both possession and the user (MFA-grade), making this a complete
// passwordless login. Returns the assertion options + an opaque session token.
func (c *KeyorixCore) BeginWebAuthnPasswordlessLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	assertion, sd, err := c.webauthnRP.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin passwordless login: %w", err)
	}
	// userID is unknown until finish resolves it from the credential's user handle.
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// FinishWebAuthnPasswordlessLogin verifies a discoverable assertion, resolves the
// user from the credential's user handle, enforces account state, and mints a
// session — a full login from a single passkey, no password.
func (c *KeyorixCore) FinishWebAuthnPasswordlessLogin(ctx context.Context, sessionToken, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData) (*models.Session, *models.User, error) {
	if c.webauthnRP == nil {
		return nil, nil, ErrWebAuthnDisabled
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired webauthn session")
	}
	if sess.Purpose != "passwordless" {
		return nil, nil, fmt.Errorf("webauthn session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return nil, nil, err
	}

	// The discoverable handler resolves the user from the 8-byte user handle that
	// the authenticator returns (our WebAuthnID encoding). ValidatePasskeyLogin then
	// verifies the assertion against that user's stored credentials.
	var resolved *models.User
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) != 8 {
			return nil, fmt.Errorf("unexpected user handle")
		}
		uid := uint(binary.BigEndian.Uint64(userHandle))
		wu, err := c.loadWebAuthnUser(ctx, uid)
		if err != nil {
			return nil, err
		}
		resolved = wu.user
		return wu, nil
	}
	_, cred, err := c.webauthnRP.ValidatePasskeyLogin(handler, sd, parsed)
	if err != nil || resolved == nil {
		c.writeAuditEventFull(ctx, "webauthn.failed", nil, nil, nil, ip, "failed passwordless WebAuthn login")
		return nil, nil, fmt.Errorf("assertion verification failed: %w", err)
	}
	// Clone-detection (#212): refuse before any other gate — a signature-counter
	// regression means this assertion may come from a cloned authenticator, so it
	// must never mint a session regardless of account state. See rejectIfCloned.
	if err := c.rejectIfCloned(ctx, resolved.ID, cred, ip); err != nil {
		return nil, nil, err
	}
	if err := c.checkPasswordlessAccountState(ctx, resolved); err != nil {
		return nil, nil, err
	}
	c.persistUpdatedCredential(ctx, resolved.ID, cred)

	if err := c.enforcePasswordExpiryGate(ctx, resolved); err != nil {
		return nil, nil, err
	}
	session, err := c.mintSession(ctx, resolved.ID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	// Record the MFA step-up window when the classification gate requires it,
	// matching both VerifyMFALogin and FinishWebAuthnLogin. A passkey satisfies
	// user-verification and is at minimum as strong as TOTP. Best-effort.
	if c.classificationRestrictedRequiresMFAStepUp {
		_ = c.storage.UpsertMFAStepupToken(ctx, resolved.ID, c.now().Add(c.mfaStepUpWindow()))
	}
	// Also mint a genuine MFAStepUpGrant, unconditionally — see the identical
	// comment in FinishWebAuthnLogin: this is the only way a WebAuthn-only
	// account can ever satisfy requireReauth's second-factor requirement, since a
	// passkey assertion has no typable "code" equivalent to a TOTP code.
	// Best-effort: a write failure does not block the login.
	_ = c.storage.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: resolved.ID, ExpiresAt: c.now().Add(c.mfaStepUpWindow())})
	uid := resolved.ID
	c.writeAuditEventFull(ctx, "webauthn.passwordless_login", &uid, nil, nil, ip,
		fmt.Sprintf("user %s logged in passwordlessly via WebAuthn", resolved.Username))
	return session, resolved, nil
}

// checkPasswordlessAccountState enforces account-state and lockout gates for a
// passwordless WebAuthn login. Extracted from FinishWebAuthnPasswordlessLogin to
// reduce its cognitive complexity.
func (c *KeyorixCore) checkPasswordlessAccountState(ctx context.Context, user *models.User) error {
	// IsActive is an independent gate from AccountState — an admin deactivation
	// (is_active=false) leaves AccountState="active", so both must be checked.
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	// Honor an active per-account lockout even for a valid passkey (defense in depth).
	// We deliberately do NOT feed failures into the lockout here — see the calling
	// comment in FinishWebAuthnPasswordlessLogin for the reasoning.
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	// Re-check under serialization before minting a session (TOCTOU guard).
	return c.checkLockAndClearLoginFailures(ctx, user)
}

// rejectIfCloned inspects a just-verified assertion's credential for a signature-
// counter regression — go-webauthn's standard FIDO2 clone-detection signal
// (Authenticator.CloneWarning), meaning this credential's private key material
// likely exists on more than one device (#212). Previously this was only ever
// written to a passive audit line while the login proceeded normally; now the
// CURRENT authentication is refused (never mints a session on a clone signal), the
// credential is disabled so it cannot authenticate again until the owner deletes it
// and registers a fresh passkey (auto re-enabling isn't safe — the stored counter
// can never again exceed a value a possibly-compromised clone already asserted),
// and the account owner is alerted loudly: a distinct audit event (superseding the
// old passive "clone_warning" line) plus an in-app/email notification, rather than
// only a silent log entry. Returns a rejection error when CloneWarning fired, nil
// otherwise (the normal, incrementing-counter case).
func (c *KeyorixCore) rejectIfCloned(ctx context.Context, userID uint, cred *webauthn.Credential, ip string) error {
	if !cred.Authenticator.CloneWarning {
		return nil
	}
	// Scoped to userID (#307) — the lookup itself enforces ownership, so no separate
	// row.UserID check is needed here.
	if row, err := c.storage.GetWebAuthnCredentialByCredID(ctx, cred.ID, userID); err == nil {
		// Mutation + audit as one unit (#1714) — see markWebAuthnCredentialClonedDisabled.
		_ = c.markWebAuthnCredentialClonedDisabled(ctx, row, ip)
	} else {
		// Row lookup failed (rare — e.g. a race with the credential being deleted
		// between assertion verification and this call). Nothing to disable, but
		// the clone signal for THIS login attempt is still real and must still be
		// recorded — this is the one case where the audit write is not paired with
		// a mutation, since there is no row to mutate.
		uid := userID
		c.writeAuditEventFull(ctx, EventWebAuthnCloneDetected, &uid, nil, nil, ip,
			fmt.Sprintf("authentication refused for user %d: signature-counter regression (possible cloned authenticator) — credential lookup failed, nothing disabled", userID))
	}
	c.notify(ctx, userID, NotificationWebAuthnCloneDetected, "Passkey clone suspected",
		"A sign-in attempt was blocked because one of your passkeys reported a signature-counter regression — a sign that its private key may exist on more than one device. The passkey has been disabled; please remove it and register a new one.",
		nil, "/account/security")
	return fmt.Errorf("assertion verification failed: signature counter did not advance (possible cloned authenticator)")
}

// markWebAuthnCredentialClonedDisabled performs a WebAuthn credential's
// disable-on-clone-signal mutation (Disabled: false -> true) and its
// EventWebAuthnCloneDetected audit write as a single unit (#1714), so no
// exported path can do one without the other. row must already be the
// caller's own fetched, owned row (rejectIfCloned's GetWebAuthnCredentialByCredID
// call scopes ownership by construction; MarkWebAuthnCredentialClonedByLookup
// below does the same for a caller that only has (credentialID, userID)).
func (c *KeyorixCore) markWebAuthnCredentialClonedDisabled(ctx context.Context, row *models.WebAuthnCredential, ip string) error {
	row.Disabled = true
	if err := c.storage.UpdateWebAuthnCredential(ctx, row); err != nil {
		return err
	}
	uid := row.UserID
	c.writeAuditEventFull(ctx, EventWebAuthnCloneDetected, &uid, nil, nil, ip,
		fmt.Sprintf("authentication refused for user %d: signature-counter regression (possible cloned authenticator) — credential disabled pending re-registration", row.UserID))
	return nil
}

// ErrWebAuthnCredentialIDMismatch is returned by MarkWebAuthnCredentialClonedByLookup
// when (credentialID, userID) resolves to a real, owned row, but that row's ID
// does not match the caller's expectedID. This is deliberately distinct from
// "not found": the pair is real and does belong to userID, it just isn't the
// SAME credential the caller is claiming to act on — a mismatch a caller must
// never have silently coerced into acting on whichever row the lookup actually
// named instead.
var ErrWebAuthnCredentialIDMismatch = errors.New("webauthn credential id does not match (credential_id, user_id)")

// MarkWebAuthnCredentialClonedByLookup explicitly disables a WebAuthn
// credential on a clone-detection signal, identified by (credentialID,
// userID) rather than an already-resolved row — the ONE thing
// UpdateWebAuthnCredentialProxy (#1714) is allowed to do. The
// GetWebAuthnCredentialByCredID lookup scopes ownership: a caller cannot
// reach a credential it doesn't legitimately identify by both its own
// credentialID and userID together, so there is no separate ownership check
// needed here, matching rejectIfCloned's own "#307" reasoning.
//
// expectedID is checked BEFORE any mutation happens — never after. An
// earlier draft of this fix fetched, mutated, and only THEN compared IDs,
// which would disable the WRONG credential (the one (credentialID, userID)
// actually named) before rejecting the request; that ordering is exactly the
// "stored row is unchanged" property callers of this function get in
// exchange for passing expectedID at all. Returns
// ErrWebAuthnCredentialIDMismatch, unmutated, if the row's real ID doesn't
// match.
func (c *KeyorixCore) MarkWebAuthnCredentialClonedByLookup(ctx context.Context, credentialID []byte, userID, expectedID uint, ip string) (*models.WebAuthnCredential, error) {
	row, err := c.storage.GetWebAuthnCredentialByCredID(ctx, credentialID, userID)
	if err != nil {
		return nil, err
	}
	if row.ID != expectedID {
		return nil, ErrWebAuthnCredentialIDMismatch
	}
	if err := c.markWebAuthnCredentialClonedDisabled(ctx, row, ip); err != nil {
		return nil, err
	}
	return row, nil
}

// persistUpdatedCredential writes back the credential's advanced signature counter
// (and clone-warning flag) plus a last-used timestamp. Best-effort: a write error
// must not fail an otherwise-valid login.
//
// Both FinishWebAuthnLogin and FinishWebAuthnPasswordlessLogin call this
// independently and unsynchronized, so a concurrent cloned-authenticator race can
// have two requests both load the stored row before either writes back: without a
// predicate, a blind Save would let the loser's stale (lower) counter overwrite the
// winner's already-persisted higher one — last UPDATE wins — silently regressing the
// on-disk counter and suppressing the clone-detection audit signal on subsequent
// logins (#306). The actual read-validate-write now happens in ONE atomic
// storage-layer call, storage.Storage.AdvanceWebAuthnCredentialCounter (#517) — see
// its doc (internal/core/storage/interface.go) for why this had to move down a
// layer: RemoteStorage.WithTransaction is a no-op passthrough (each remote call is
// independent), so composing LockWebAuthnCredentialForUpdate + UpdateWebAuthnCredential
// as two separate remote round trips (as this function used to, against
// LocalStorage only) would reopen the exact TOCTOU race the transaction was built to
// prevent. webauthnCredentialMu still serializes same-process callers (belt-and-
// suspenders for the single-process SQLite case, where AdvanceWebAuthnCredentialCounter's
// own row lock is a no-op); combined with LocalStorage's row lock on Postgres, or the
// upstream server's own equivalent lock for a storage.type: remote deployment, the
// counter stays monotonic across replicas too.
func (c *KeyorixCore) persistUpdatedCredential(ctx context.Context, userID uint, cred *webauthn.Credential) {
	blob, err := json.Marshal(cred)
	if err != nil {
		return
	}
	now := c.now()

	c.webauthnCredentialMu.Lock()
	defer c.webauthnCredentialMu.Unlock()

	_, _ = c.storage.AdvanceWebAuthnCredentialCounter(ctx, cred.ID, userID, blob, cred.Authenticator.SignCount, now)
}

func (c *KeyorixCore) auditWebAuthnFailed(ctx context.Context, userID uint, phase string) {
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.failed", &uid, nil, nil, "",
		fmt.Sprintf("failed WebAuthn %s for user %d", phase, userID))
}
