// auth.go — Session authentication: Login, Logout, RefreshSession, ValidateSessionToken.
//
// For first-boot system bootstrap see auth_bootstrap.go.
package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// sessionTouchInterval throttles last_seen_at writes on the auth hot path.
const sessionTouchInterval = 30 * time.Second

// defaultSessionAccessTTL is the access-token lifetime when no session config is
// set. It matches the historic hard-coded value, so an install that does not
// configure a session block keeps the old 24h behaviour.
const defaultSessionAccessTTL = 24 * time.Hour

// accessTTL returns the configured access-token lifetime, or the 24h default.
func (c *KeyorixCore) accessTTL() time.Duration {
	if c.sessionAccessTTL > 0 {
		return c.sessionAccessTTL
	}
	return defaultSessionAccessTTL
}

// LoginRequest holds credentials for login. UserAgent/IPAddress are captured for
// the My Account "active sessions" view and are optional.
type LoginRequest struct {
	Username  string
	Password  string
	UserAgent string
	IPAddress string
}

// RemoteLoginVerifier is implemented by storage backends that cannot themselves
// supply a real password hash for VerifyPasswordCredentials to compare against
// (#506): models.User.PasswordHash is deliberately `json:"-"` and NEVER crosses
// the wire, so RemoteStorage's GetUserByUsername always comes back with an
// empty hash, and a bcrypt compare against it would fail unconditionally — every
// password login was permanently broken under storage.type: remote before this.
//
// The fix is a proxy-login channel: the upstream server (the one actually
// backed by LocalStorage, which HAS the real hash) performs the credential
// check itself and returns only a verdict, never the hash. RemoteStorage
// implements this interface by forwarding to a POST
// /api/v1/users/verify-credentials endpoint, whose handler calls the
// UPSTREAM's own core.Login — the SAME function the direct LocalStorage path
// uses, not a parallel reimplementation of the bcrypt compare or of session
// minting. Critically, this means the ENTIRE check is delegated — password
// compare AND the per-account lockout gate/accounting AND the account-active/
// account-state checks — not just a bare boolean. Splitting the lockout
// accounting out and leaving it client-side would be a silent regression:
// login_lockout.go's UpdateLoginLockoutState is a permanent, unconditional
// stub under RemoteStorage (#454 — the wire format has no columns for it), so
// a client-side-only lockout gate can never actually persist a trip and would
// leave storage.type: remote with NO per-account brute-force backstop at all
// (only the separate, coarser per-IP rate limiter, #452). Proxying the whole
// check to the upstream's real, LocalStorage-persisted accounting is the only
// way this deployment shape can enforce it.
//
// #508 — session minting is ATOMIC with verification, not a second, separate
// step: VerifyLoginCredentials returns the upstream-minted *models.Session in
// the SAME call that proved the password correct, exactly when the account
// needs no MFA/WebAuthn second factor (mirroring Login's own gate below). A
// nil session with a nil error means the account requires MFA/WebAuthn — the
// upstream deliberately withheld a session for that case, just as Login does
// for the direct LocalStorage path. There is deliberately NO separate,
// independently-callable "create a session for this user_id" wire primitive:
// that would let anyone holding the RemoteStorage service credential mint a
// session for an arbitrary user without ever proving that user's actual
// credentials (a confused-deputy / privilege-escalation oracle). Tying
// issuance inseparably to a specific, just-completed verification — the same
// pattern OAuth/OIDC token-exchange flows use — is what makes this safe.
type RemoteLoginVerifier interface {
	VerifyLoginCredentials(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error)
}

// VerifyPasswordCredentials resolves "is this username/password combination
// valid", enforcing the per-account lockout gate and the account-active/
// account-state checks Login has always required — extracted out of Login
// (#506) as the single source of truth for the LOCAL bcrypt-backed check.
//
// This never delegates to RemoteLoginVerifier (see Login below for that
// dispatch): under storage.type: remote, calling this directly always fails
// closed (RemoteStorage.GetUserByUsername's decoded user always has an empty
// PasswordHash, so the bcrypt compare below can never succeed) — exactly the
// same fail-closed behavior storage.type: remote password login had before
// #506. The only supported entry point for a proxied, storage.type: remote
// login is Login itself, which mints (or, via the proxy, receives) a session
// atomically with verification (#508) — a capability this function
// deliberately does not have, since it returns no session.
func (c *KeyorixCore) VerifyPasswordCredentials(ctx context.Context, username, password string) (*models.User, error) {
	user, err := c.storage.GetUserByUsername(ctx, username)
	if err != nil {
		// Spend an equivalent bcrypt comparison so a missing username doesn't return
		// faster than a wrong password (account-enumeration timing side-channel).
		_ = bcrypt.CompareHashAndPassword(*dummyBcryptHash.Load(), []byte(password))
		return nil, fmt.Errorf("invalid credentials")
	}
	// Per-account lockout gate: while locked, refuse regardless of the password, so
	// repeated guessing can't progress. Spend an equivalent bcrypt comparison first so the
	// locked path's latency matches the unknown-user and wrong-password paths — otherwise a
	// fast (no-bcrypt) response on a locked account is a username-existence oracle (the
	// attacker first forces the lockout, then probes by timing).
	if c.loginLocked(user) {
		_ = bcrypt.CompareHashAndPassword(*dummyBcryptHash.Load(), []byte(password))
		return nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		c.recordFailedLogin(ctx, user) // increment + lock at the threshold
		return nil, fmt.Errorf("invalid credentials")
	}
	// Correct password — but this is only PARTIAL authentication when the account
	// has a second factor configured (MFAEnabled/WebAuthnEnabled): Login refuses to
	// mint a session at this point and instead returns ErrMFARequired, deferring to
	// CreateMFAChallenge -> VerifyMFALogin (or the WebAuthn assertion ceremony).
	// Deliberately do NOT clear the accumulated lockout state here: this function
	// has no visibility into whether a second factor is required (that gate lives
	// in the caller, Login), so clearing unconditionally would let an attacker who
	// merely knows the correct password — without ever passing MFA — repeatedly
	// reset the account's failed-login counter/lock, defeating the lockout as a
	// brute-force backstop and even undoing a defender-triggered lock. The
	// TOCTOU-safe recheck-and-clear (checkLockAndClearLoginFailures) instead
	// happens at the ACTUAL full-authentication point for each login path: Login
	// itself, immediately before mintSession, when no second factor is required;
	// VerifyMFALogin and the WebAuthn Finish* functions, immediately before their
	// own mintSession, when one is. Every login path ends up covered exactly once,
	// at the point it is truly done authenticating — never earlier.
	// A deactivated account (IsActive=false — e.g. admin deactivation via UpdateUser,
	// or a SCIM/IdP deactivation) is refused login regardless of account_state. The
	// state-based gate below does not cover this, so without it a deactivated user who
	// still knew their password could authenticate; it also lets SCIM deactivation
	// preserve a restricted account_state (forced reset) while still blocking login.
	if !user.IsActive {
		return nil, fmt.Errorf("account is not active")
	}
	// A suspended account is refused login outright (ADR-025). Restricted states
	// (pending_first_login / password_reset_required) still log in, but the auth
	// middleware confines the session to the password-change allowlist.
	if AccountLoginBlocked(user.AccountState) {
		return nil, fmt.Errorf("account suspended")
	}
	return user, nil
}

// Login validates credentials, creates a session, and returns (session, user, error).
//
// #508: under storage.type: remote (c.storage implements RemoteLoginVerifier),
// verification and session minting happen as ONE atomic upstream call —
// VerifyLoginCredentials returns the upstream-minted session directly,
// mirroring the MFA gate below exactly (a nil session means the upstream
// itself withheld one because the account needs a second factor). Login never
// separately asks the upstream to "create a session for this user" after the
// fact — see RemoteLoginVerifier's doc for why that split would be unsafe.
func (c *KeyorixCore) Login(ctx context.Context, req *LoginRequest) (*models.Session, *models.User, error) {
	if verifier, ok := c.storage.(RemoteLoginVerifier); ok {
		user, session, err := verifier.VerifyLoginCredentials(ctx, req.Username, req.Password, req.UserAgent, req.IPAddress)
		if err != nil {
			return nil, nil, err
		}
		if user.MFAEnabled || user.WebAuthnEnabled {
			return nil, user, ErrMFARequired
		}
		if session == nil {
			// Defensive, should not happen: the upstream reported no MFA/WebAuthn gate
			// but withheld a session anyway. Fail closed rather than let the caller
			// proceed with no usable session.
			return nil, nil, fmt.Errorf("failed to create session: upstream did not return one")
		}
		return session, user, nil
	}

	user, err := c.VerifyPasswordCredentials(ctx, req.Username, req.Password)
	if err != nil {
		return nil, nil, err
	}
	// Enforce the password max-age policy: if the password has expired, gate the
	// account to password_reset_required NOW so the middleware blocks API access
	// on every subsequent request (ADR-025 hard gate). The soft flag in the login
	// response alone is not sufficient — a client that ignores it would retain
	// full API access indefinitely.
	if err := c.enforcePasswordExpiryGate(ctx, user); err != nil {
		return nil, nil, err
	}
	// Accounts with any second factor (TOTP or a passkey) get no session from the
	// password step — the caller must complete it (CreateMFAChallenge →
	// VerifyMFALogin for TOTP, or the WebAuthn assertion ceremony for a passkey).
	// Critically, the lockout counter is NOT cleared on this branch: a correct
	// password alone is not full authentication for these accounts, so an
	// attacker who knows the password but lacks the second factor must not be
	// able to reset the account's brute-force lockout state (VerifyMFALogin /
	// the WebAuthn Finish* functions each do their own clear once the second
	// factor actually succeeds).
	if user.MFAEnabled || user.WebAuthnEnabled {
		return nil, user, ErrMFARequired
	}
	// No second factor configured — the password step IS the full authentication.
	// Re-check the lock state under the same serialization recordFailedLogin uses
	// (the account's mutex shard + a Postgres row lock) before minting a session,
	// and only then clear any accumulated failure state: a concurrent burst of
	// failed attempts against this account may have tripped the lock between the
	// snapshot read inside VerifyPasswordCredentials and now (TOCTOU) — never
	// trust that stale snapshot alone.
	if err := c.checkLockAndClearLoginFailures(ctx, user); err != nil {
		return nil, nil, err
	}
	created, err := c.mintSession(ctx, user.ID, req.UserAgent, req.IPAddress)
	if err != nil {
		return nil, nil, err
	}
	return created, user, nil
}

// mintSession creates and persists a new session token for a user. The access
// window is the configured access TTL (default 24h); when an absolute ceiling is
// configured it is stamped once here and carried unchanged through every refresh,
// so total session lifetime is bounded regardless of how often the token rotates.
// Shared by Login and the setup-token consume flow (auto-login) so session
// issuance — token generation, expiry, and the captured device fields — stays uniform.
func (c *KeyorixCore) mintSession(ctx context.Context, userID uint, userAgent, ip string) (*models.Session, error) {
	token, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	// FamilyID starts a new lineage at login and is carried unchanged through every
	// RefreshSession rotation, so a detected refresh-token reuse can revoke the whole
	// chain in one shot (#211).
	familyID, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session family id: %w", err)
	}
	now := c.now()
	expiresAt := now.Add(c.accessTTL())
	session := &models.Session{
		UserID:       userID,
		SessionToken: token,
		FamilyID:     familyID,
		UserAgent:    userAgent,
		IPAddress:    ip,
		LastSeenAt:   &now,
		ExpiresAt:    &expiresAt,
	}
	if c.sessionAbsoluteTTL > 0 {
		absolute := now.Add(c.sessionAbsoluteTTL)
		// A ceiling shorter than one access window is meaningless — never let the
		// first window already overrun the ceiling.
		if absolute.Before(expiresAt) {
			absolute = expiresAt
		}
		session.AbsoluteExpiresAt = &absolute
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	// Bound concurrent sessions per user so unbounded logins can't grow the table or
	// enlarge the credential-theft blast radius. Best-effort — never fail a login on it.
	_ = c.storage.EnforceSessionLimit(ctx, userID, maxSessionsPerUser)
	return created, nil
}

// maxSessionsPerUser caps a user's concurrent sessions; the oldest beyond this are
// reaped on each new login (see EnforceSessionLimit).
const maxSessionsPerUser = 25

// RecordLogin stamps the user's last_login_at to the current time. Best-effort:
// the login handler calls this in a goroutine after a successful authentication,
// so a storage error here must never fail the login itself.
//
// G81: normalized to UTC here explicitly rather than via a models.User BeforeSave
// hook — UpdateLastLogin's sole write path (local_users.go, UpdateColumn) bypasses
// all model hooks, so a hook would be silently ineffective (see the doc comment on
// User.LastLoginAt). Mirrors local_mfa_stepup.go's explicit-normalization fix for
// MFAStepupToken's ON CONFLICT path, which has the same hook-bypass shape.
func (c *KeyorixCore) RecordLogin(ctx context.Context, userID uint) error {
	return c.storage.UpdateLastLogin(ctx, userID, c.now().UTC())
}

// Logout invalidates the session identified by token.
func (c *KeyorixCore) Logout(ctx context.Context, token string) error {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return fmt.Errorf("session not found")
	}
	return c.storage.DeleteSession(ctx, session.ID)
}

// GetSessionForRemoteProxy resolves a session by its presented plaintext token.
// It is the server-side counterpart RemoteStorage.GetSession (#508) needs so a
// storage.type: remote "spoke" deployment can validate/revoke sessions that
// were minted upstream — the upstream server remains the sole source of truth
// for session validity, exactly as it already is for the user record and
// password hash (#505/#506). Unlike VerifyLoginCredentials, this performs NO
// credential check of its own: it only ever returns a session for a caller who
// already presents that session's own opaque token (a lookup, not a mint), so
// it cannot be used to obtain access to an account without already holding one
// of its live session tokens.
func (c *KeyorixCore) GetSessionForRemoteProxy(ctx context.Context, token string) (*models.Session, error) {
	return c.storage.GetSession(ctx, token)
}

// DeleteSessionForRemoteProxy deletes a session by its numeric ID — the
// server-side counterpart RemoteStorage.DeleteSession (#508) needs so Logout
// (and any other session-invalidation path) works end-to-end under
// storage.type: remote. Gated the same way VerifyLoginCredentials/CreateUser/
// UnlockUser already are (users.write on the RemoteStorage service credential,
// server/http/router.go) — not a new, wider trust boundary: that credential
// can already force-logout an arbitrary user's every session via
// RevokeUserSessions (POST /users/{id}/revoke-sessions), so deleting a single
// session by ID grants no capability beyond what is already accepted there.
// Evicts the deleted session's token hash from the local auth cache too, so a
// revoke takes effect immediately rather than lingering for the cache TTL if
// this same process also happens to be validating that exact token directly.
func (c *KeyorixCore) DeleteSessionForRemoteProxy(ctx context.Context, id uint) error {
	session, lookupErr := c.storage.GetSessionByID(ctx, id)
	if err := c.storage.DeleteSession(ctx, id); err != nil {
		return err
	}
	if lookupErr == nil {
		c.invalidateTokenCache(session.SessionToken)
	}
	return nil
}

// EventSessionReuseDetected audits a refresh attempt against an already-rotated
// session token (#211) — distinct from the generic "session not found" a caller
// sees, since a rotated-away token is either a genuine refresh-token-reuse replay
// (a standard OAuth compromise signal) or a benign concurrent-refresh race loser;
// the DB alone cannot tell those apart, so both are treated as suspicious and the
// whole session family is revoked.
const EventSessionReuseDetected = "auth.session_reuse_detected" // #nosec G101 -- audit event type, not a credential

// RefreshSession rotates an existing session to a new token with a fresh access
// window. The access window may have lapsed — that is the normal silent-refresh
// case — but refresh is refused once the session's absolute ceiling is reached, so
// rotating the token can never extend a session indefinitely. The ceiling is
// carried unchanged onto the new session, and the new access window is clamped so
// it never overruns that ceiling.
//
// Rotation is atomic (RotateSession is a single DB transaction with a CAS guard —
// #211): a replay of a token that has already been rotated away, or a race where
// two concurrent refreshes target the same not-yet-rotated token, both surface here
// as "lost the rotation" and are handled identically — audited distinctly from
// ordinary expiry and the whole session family (every session descended from the
// same login) is revoked, not just the one replayed row.
func (c *KeyorixCore) RefreshSession(ctx context.Context, token string) (*models.Session, error) {
	old, err := c.storage.GetSessionAny(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	now := c.now()
	if old.RotatedAt != nil {
		// The token maps to a session that was already rotated away by an earlier,
		// successful refresh — a reuse of a stale refresh token.
		c.handleSessionReuse(ctx, old)
		return nil, fmt.Errorf("session not found or expired")
	}
	if old.AbsoluteExpiresAt != nil && !now.Before(*old.AbsoluteExpiresAt) {
		// Past the hard ceiling — re-authentication required, not another refresh.
		_ = c.storage.DeleteSession(ctx, old.ID)
		return nil, fmt.Errorf("session lifetime exceeded; re-authentication required")
	}
	// An impersonation session must not be refreshable. /auth/refresh is public (any
	// bearer token), and refresh rebuilds the session without the impersonation fields —
	// so refreshing an impersonation token would mint a fresh, full-TTL session for the
	// target with the impersonated_by attribution stripped, laundering a bounded, audited
	// support session into unbounded, unattributed account access. The admin keeps their
	// own session and swaps back via "Return to Admin".
	if old.ImpersonatedBy != nil {
		return nil, fmt.Errorf("impersonation sessions cannot be refreshed")
	}
	// Re-check account state before rotating the token. ValidateSessionToken applies
	// this gate on every request, but refresh is a distinct, unauthenticated-by-token
	// entry point: without re-checking here, an account deactivated (IsActive=false)
	// or suspended after issuance could keep minting fresh, self-renewing sessions
	// indefinitely. Mirror the gate and drop the now-invalid session.
	user, err := c.storage.GetUser(ctx, old.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.IsActive || AccountLoginBlocked(user.AccountState) {
		_ = c.storage.DeleteSession(ctx, old.ID)
		return nil, fmt.Errorf("account is not active")
	}
	newToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	expiresAt := now.Add(c.accessTTL())
	if old.AbsoluteExpiresAt != nil && expiresAt.After(*old.AbsoluteExpiresAt) {
		expiresAt = *old.AbsoluteExpiresAt
	}
	familyID, err := ensureFamilyID(old.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	session := &models.Session{
		UserID:            old.UserID,
		SessionToken:      newToken,
		FamilyID:          familyID,
		UserAgent:         old.UserAgent,
		IPAddress:         old.IPAddress,
		LastSeenAt:        &now,
		ExpiresAt:         &expiresAt,
		AbsoluteExpiresAt: old.AbsoluteExpiresAt,
	}
	created, won, err := c.storage.RotateSession(ctx, old.ID, session, now)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate session: %w", err)
	}
	if !won {
		// Lost the CAS: a concurrent refresh of this exact token won first between
		// our read and our write. Same signal as an out-of-band replay.
		c.handleSessionReuse(ctx, old)
		return nil, fmt.Errorf("session not found or expired")
	}
	return created, nil
}

// ensureFamilyID returns existing if non-empty, otherwise generates a new secure token.
// Legacy sessions pre-dating FamilyID have an empty field; we start a fresh lineage
// rather than leaving it empty to avoid grouping all legacy sessions under one family.
func ensureFamilyID(existing string) (string, error) {
	if existing != "" {
		return existing, nil
	}
	return generateSecureToken()
}

// handleSessionReuse responds to a refresh attempt that targeted an already-rotated
// session token (#211): audits it distinctly from ordinary "not found"/expiry, and
// revokes every session descended from the same login (FamilyID) — not just the one
// replayed row — mirroring standard OAuth refresh-token-family revocation. Each
// revoked session's token hash is evicted from the HTTP auth cache immediately, so
// the attacker's already-rotated descendant session (if any) stops authenticating on
// the very next request rather than lingering for the cache TTL.
func (c *KeyorixCore) handleSessionReuse(ctx context.Context, old *models.Session) {
	uid := old.UserID
	c.writeAuditEventFull(ctx, EventSessionReuseDetected, &uid, nil, nil, old.IPAddress,
		fmt.Sprintf("refresh attempted with an already-rotated session token for user %d — revoking the session family", old.UserID))
	if old.FamilyID == "" {
		// Legacy row predating FamilyID — fall back to revoking just this one row.
		_ = c.storage.DeleteSession(ctx, old.ID)
		return
	}
	hashes, _ := c.storage.ListSessionTokenHashesByFamily(ctx, old.FamilyID)
	_ = c.storage.DeleteSessionsByFamily(ctx, old.FamilyID)
	for _, h := range hashes {
		if h != "" {
			c.invalidateTokenCache(h)
		}
	}
}

// ValidateSessionToken looks up a session token, checks expiry, and returns the user and
// their role names. Used by the auth middleware on every authenticated request.
func (c *KeyorixCore) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("session not found")
	}
	if session.ExpiresAt != nil && c.now().After(*session.ExpiresAt) {
		return nil, nil, fmt.Errorf("session expired")
	}
	// Enforce the hard absolute-lifetime ceiling at the validation boundary, not only via
	// the clamp RefreshSession/mintSession apply to ExpiresAt. The clamp makes an expired
	// ceiling imply an expired access window in normal operation, but the ceiling must not
	// DEPEND on every issuer having clamped correctly — a session whose access window is
	// still open yet whose ceiling has passed (a future non-clamping path, or a tampered
	// row) is rejected here. Self-checking invariant.
	if session.AbsoluteExpiresAt != nil && c.now().After(*session.AbsoluteExpiresAt) {
		return nil, nil, fmt.Errorf("session lifetime exceeded")
	}
	user, err := c.storage.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}
	// Reject sessions whose account has since been deactivated or suspended, so an
	// admin's suspend/deactivate takes effect on already-issued tokens rather than
	// lingering until expiry. Mirrors the active-state check in ValidatePATToken.
	if !user.IsActive || AccountLoginBlocked(user.AccountState) {
		return nil, nil, fmt.Errorf("account is not active")
	}
	// For an impersonation session (acting AS session.UserID on behalf of an admin),
	// the impersonating admin's account must still be valid too — otherwise suspending
	// or deactivating the admin would not stop their in-flight impersonation, since the
	// session is keyed to the target's user_id and the gate above only checks the
	// target. Self-checking backstop alongside the session purge on state change.
	// MT-007/#G05: re-verify both the admin's active state and the ceiling (not
	// just the target's, checked above) so neither an elevation of the target's
	// roles NOR a demotion/suspension of the impersonating admin after
	// impersonation started silently persists for the rest of the session.
	// Cached (IMP-001) to avoid repeated DB queries on every session validation;
	// cache TTL is 2× the auth-cache window. See ReauthorizeImpersonation's doc
	// comment (impersonation.go) — StreamAuditLogs' dedicated re-auth ticker
	// (#108) runs the identical check for long-lived gRPC streams.
	if session.ImpersonatedBy != nil && *session.ImpersonatedBy != 0 {
		if err := c.ReauthorizeImpersonation(ctx, *session.ImpersonatedBy, session.UserID); err != nil {
			return nil, nil, err
		}
	}
	// Best-effort, throttled last-seen stamp for the My Account sessions view.
	// Only writes when the stored value is older than sessionTouchInterval, so the
	// auth hot path is not turned into a write per request. Never fails the request.
	// Stamped only AFTER the account-state gate, so a rejected request from a
	// suspended/deactivated account is not "used" — it must not refresh last-seen
	// (matching ValidatePATToken, which touches only after the same gate).
	_ = c.storage.TouchSession(ctx, session.ID, c.now(), sessionTouchInterval)
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return user, []string{}, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, nil
}

// SessionStillLive reports whether the session row sessionID is still the LIVE
// credential it was when it authenticated a long-lived gRPC stream (#G18).
// StreamAuditLogs' periodic reauthorizeAuditStream tick previously re-checked
// only the owning account's state (GetUser/IsActive/AccountLoginBlocked), never
// the SPECIFIC session that opened the stream — so an individually revoked
// session (e.g. "log out this device", or DeleteSessionsForUserExcept from a
// password change) kept receiving the live feed for the rest of the stream's
// lifetime, since account-level checks alone can't see that. Deliberately keyed
// by the session's numeric row id, not its raw token or hash: the token is
// validated once at stream-open and is not retained afterward (security
// hygiene — the gRPC auth interceptor tags UserContext.SessionID, a
// non-sensitive identifier, instead). Mirrors ValidateSessionToken's own
// liveness checks (row exists, not rotated away, within both the access-window
// and absolute-lifetime ceilings) without repeating its account-state gate —
// reauthorizeAuditStream already runs that check independently.
func (c *KeyorixCore) SessionStillLive(ctx context.Context, sessionID uint) (bool, error) {
	session, err := c.storage.GetSessionByID(ctx, sessionID)
	if err != nil {
		return false, err
	}
	if session.RotatedAt != nil {
		return false, nil
	}
	now := c.now()
	if session.ExpiresAt != nil && now.After(*session.ExpiresAt) {
		return false, nil
	}
	if session.AbsoluteExpiresAt != nil && now.After(*session.AbsoluteExpiresAt) {
		return false, nil
	}
	return true, nil
}

// AccountStillUsable reports whether userID's account is still active and not
// login-blocked (ADR-025) — the same account-state gate ValidateSessionToken's
// slow path already applies, factored out so the auth middleware's cache-hit
// path (#G18) can re-check it on every request instead of only once per
// validTokenTTL. A user deactivated or suspended mid-window previously kept
// authenticating via the positive session cache for up to 30s after the
// slow-path re-validation would have rejected them outright.
func (c *KeyorixCore) AccountStillUsable(ctx context.Context, userID uint) (bool, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.IsActive && !AccountLoginBlocked(user.AccountState), nil
}

// RequestPasswordReset issues a password-reset link for the given email and
// delivers it via the configured credential-delivery channel (ADR-028). The
// recipient consumes it at /auth/setup/{token} to set a new password
// (completePasswordSetup handles the password_reset_link purpose).
//
// Always returns nil: the outcome must not reveal whether the email maps to an
// account (enumeration-safe), so unknown addresses, suspended accounts, throttled
// repeats, and delivery/config failures are all swallowed. The attempt itself is
// audited inside provisionSetupLink.
//
// #117: the known-account path used to synchronously dial-and-send the email
// (SMTP delivery blocks on the real network round-trip) before returning, while
// an unknown/blocked/SSO-managed address returned after a single fast DB lookup
// — a measurable timing side-channel an attacker can use to enumerate valid
// accounts without ever seeing a different response body. The issue+deliver
// step now runs detached in the background (DetachedAuditContext, the same
// fire-and-forget pattern used elsewhere for post-response audit work) so this
// function returns at the same speed regardless of whether the email exists.
func (c *KeyorixCore) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil // Don't reveal whether the email exists.
	}
	// Never send a reset to a login-blocked (e.g. suspended) account.
	if AccountLoginBlocked(user.AccountState) {
		return nil
	}
	// Refuse for externally-managed identities (SSO/SCIM): issuing a local password
	// would create a backdoor that authenticates at /auth/login and bypasses the IdP's
	// MFA / conditional access / deprovisioning. Swallowed to stay enumeration-safe.
	if user.ExternalID != "" {
		return nil
	}
	// Throttle abusive repeats to a victim address (same control as resend). A
	// throttled repeat returns an error here, swallowed below to stay enumeration-safe.
	// Detached from the request context: the HTTP handler returns immediately after
	// this call, which would cancel a request-scoped ctx before the SMTP send (or
	// even the throttle check) completes.
	detached := DetachedAuditContext(ctx)
	goSafe(func() {
		_, _ = c.provisionSetupLinkThrottled(detached, IssueSetupTokenRequest{
			Purpose:       SetupPurposePasswordResetLink,
			SubjectEmail:  user.Email,
			SubjectUserID: &user.ID,
			CreatedBy:     0, // self-service (no issuing admin)
		}, user.DisplayName, "")
	})
	return nil
}

// generateSecureToken creates a cryptographically random 32-byte hex token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
