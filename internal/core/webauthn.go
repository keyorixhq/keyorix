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
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrWebAuthnDisabled is returned when a WebAuthn operation is attempted but the
// server has no relying party configured (no webauthn block in the config).
var ErrWebAuthnDisabled = errors.New("webauthn is not enabled on this server")

const webauthnSessionTTL = 5 * time.Minute

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
func (c *KeyorixCore) FinishWebAuthnRegistration(ctx context.Context, userID uint, sessionToken, name string, parsed *protocol.ParsedCredentialCreationData) (*models.WebAuthnCredential, error) {
	if c.webauthnRP == nil {
		return nil, ErrWebAuthnDisabled
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
// last one, WebAuthn is disabled for the account.
func (c *KeyorixCore) DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error {
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
	assertion, sd, err := c.webauthnRP.BeginLogin(wu)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin login: %w", err)
	}
	token, err := c.storeWebAuthnSession(ctx, ch.UserID, "login", sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
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
	if !wu.user.IsActive || AccountLoginBlocked(wu.user.AccountState) {
		return nil, nil, fmt.Errorf("account is not active")
	}
	// Per-account lockout also gates the WebAuthn second factor (parity with the TOTP
	// path in VerifyMFALogin): the per-IP limiter is spoofable behind a proxy and fails
	// open, so bind assertion failures to the account. ch.UserID comes from the
	// password-gated challenge (not an attacker-chosen handle), so this cannot be abused
	// to lock out an arbitrary victim.
	if c.loginLocked(wu.user) {
		return nil, nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	cred, err := c.webauthnRP.ValidateLogin(wu, sd, parsed)
	if err != nil {
		c.auditWebAuthnFailed(ctx, ch.UserID, "login")
		c.recordFailedLogin(ctx, wu.user) // count the failed second factor toward the lockout
		return nil, nil, fmt.Errorf("assertion verification failed: %w", err)
	}
	// A concurrent burst of failed second-factor attempts against this account may
	// have tripped the lock since the pre-verification snapshot check above
	// (TOCTOU). Re-check under the same serialization recordFailedLogin uses
	// before minting a session.
	if err := c.checkLockAndClearLoginFailures(ctx, wu.user); err != nil {
		return nil, nil, err
	}
	c.persistUpdatedCredential(ctx, ch.UserID, cred)

	session, err := c.mintSession(ctx, ch.UserID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	uid := ch.UserID
	if cred.Authenticator.CloneWarning {
		c.writeAuditEventFull(ctx, "webauthn.clone_warning", &uid, nil, nil, ip,
			fmt.Sprintf("possible cloned authenticator for user %s (signature counter did not advance)", wu.user.Username))
	}
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
	// A passwordless login is still a login: a deactivated or suspended/blocked account
	// is refused. IsActive is an independent gate from AccountState — an admin
	// deactivation (is_active=false) leaves AccountState="active", so checking only
	// AccountLoginBlocked would let a disabled account in. Mirrors the 2FA and password
	// gates.
	if !resolved.IsActive || AccountLoginBlocked(resolved.AccountState) {
		return nil, nil, fmt.Errorf("account is not active")
	}
	// Honor an active per-account lockout even for a valid passkey (defense in depth —
	// e.g. the account was locked via the password path). We deliberately do NOT feed
	// failures into the lockout here: a discoverable login resolves the user from an
	// attacker-chosen user handle, so counting failed assertions would let an attacker
	// lock out an arbitrary victim. The unforgeable assertion signature is the real
	// throttle, backed by the per-IP limiter.
	if c.loginLocked(resolved) {
		return nil, nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	// Re-check the lock state under the same serialization recordFailedLogin uses
	// before minting a session — the passwordless path does not feed failures into
	// the lockout itself (see above), but the account could still have been locked
	// concurrently via the password/2FA path between the snapshot check above and
	// here (TOCTOU).
	if err := c.checkLockAndClearLoginFailures(ctx, resolved); err != nil {
		return nil, nil, err
	}
	c.persistUpdatedCredential(ctx, resolved.ID, cred)

	session, err := c.mintSession(ctx, resolved.ID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	uid := resolved.ID
	if cred.Authenticator.CloneWarning {
		c.writeAuditEventFull(ctx, "webauthn.clone_warning", &uid, nil, nil, ip,
			fmt.Sprintf("possible cloned authenticator for user %s (signature counter did not advance)", resolved.Username))
	}
	c.writeAuditEventFull(ctx, "webauthn.passwordless_login", &uid, nil, nil, ip,
		fmt.Sprintf("user %s logged in passwordlessly via WebAuthn", resolved.Username))
	return session, resolved, nil
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
// logins (#306). webauthnCredentialMu serializes same-process callers (and so the
// whole single-process SQLite case); combined with the row lock
// LockWebAuthnCredentialForUpdate takes on Postgres, the read-validate-write stays
// correct across replicas too. Inside the transaction the counter check is re-done
// against the row's CURRENT persisted value (re-read under the lock), not the value
// `cred` was validated against at the top of Finish*Login, so only a genuinely higher
// counter is ever persisted.
func (c *KeyorixCore) persistUpdatedCredential(ctx context.Context, userID uint, cred *webauthn.Credential) {
	blob, err := json.Marshal(cred)
	if err != nil {
		return
	}
	now := c.now()

	c.webauthnCredentialMu.Lock()
	defer c.webauthnCredentialMu.Unlock()

	_ = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		row, err := tx.LockWebAuthnCredentialForUpdate(ctx, cred.ID, userID)
		if err != nil {
			return err
		}
		var stored webauthn.Credential
		if err := json.Unmarshal(row.CredentialBlob, &stored); err != nil {
			return err
		}
		// Mirrors go-webauthn's own Authenticator.UpdateCounter gate: many platform
		// authenticators (Touch ID, Windows Hello, and most passkeys) never implement a
		// counter and always report 0, so a (0, 0) comparison must NOT be treated as
		// stale — that would silently stop LastUsedAt/blob updates from ever persisting
		// again for the common case. Only reject when at least one side is nonzero and
		// the new value fails to advance past the row's CURRENT stored value.
		newCount, storedCount := cred.Authenticator.SignCount, stored.Authenticator.SignCount
		if newCount <= storedCount && (newCount != 0 || storedCount != 0) {
			// A concurrent request already advanced the stored counter past (or to) this
			// assertion's value: this write is stale, so skip it rather than regress the
			// persisted counter.
			return nil
		}
		row.CredentialBlob = blob
		row.LastUsedAt = &now
		return tx.UpdateWebAuthnCredential(ctx, row)
	})
}

func (c *KeyorixCore) auditWebAuthnFailed(ctx context.Context, userID uint, phase string) {
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.failed", &uid, nil, nil, "",
		fmt.Sprintf("failed WebAuthn %s for user %d", phase, userID))
}
