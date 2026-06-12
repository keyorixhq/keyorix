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

// Login validates credentials, creates a session, and returns (session, user, error).
func (c *KeyorixCore) Login(ctx context.Context, req *LoginRequest) (*models.Session, *models.User, error) {
	user, err := c.storage.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	// A suspended account is refused login outright (ADR-025). Restricted states
	// (pending_first_login / password_reset_required) still log in, but the auth
	// middleware confines the session to the password-change allowlist.
	if AccountLoginBlocked(user.AccountState) {
		return nil, nil, fmt.Errorf("account suspended")
	}
	// MFA-enabled accounts get no session from the password step — the caller must
	// complete the second factor (CreateMFAChallenge → VerifyMFALogin).
	if user.MFAEnabled {
		return nil, user, ErrMFARequired
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
	now := c.now()
	expiresAt := now.Add(c.accessTTL())
	session := &models.Session{
		UserID:       userID,
		SessionToken: token,
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
	return created, nil
}

// RecordLogin stamps the user's last_login_at to the current time. Best-effort:
// the login handler calls this in a goroutine after a successful authentication,
// so a storage error here must never fail the login itself.
func (c *KeyorixCore) RecordLogin(ctx context.Context, userID uint) error {
	return c.storage.UpdateLastLogin(ctx, userID, c.now())
}

// Logout invalidates the session identified by token.
func (c *KeyorixCore) Logout(ctx context.Context, token string) error {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return fmt.Errorf("session not found")
	}
	return c.storage.DeleteSession(ctx, session.ID)
}

// RefreshSession rotates an existing session to a new token with a fresh access
// window. The access window may have lapsed — that is the normal silent-refresh
// case — but refresh is refused once the session's absolute ceiling is reached, so
// rotating the token can never extend a session indefinitely. The ceiling is
// carried unchanged onto the new session, and the new access window is clamped so
// it never overruns that ceiling.
func (c *KeyorixCore) RefreshSession(ctx context.Context, token string) (*models.Session, error) {
	old, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	now := c.now()
	if old.AbsoluteExpiresAt != nil && !now.Before(*old.AbsoluteExpiresAt) {
		// Past the hard ceiling — re-authentication required, not another refresh.
		_ = c.storage.DeleteSession(ctx, old.ID)
		return nil, fmt.Errorf("session lifetime exceeded; re-authentication required")
	}
	newToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	expiresAt := now.Add(c.accessTTL())
	if old.AbsoluteExpiresAt != nil && expiresAt.After(*old.AbsoluteExpiresAt) {
		expiresAt = *old.AbsoluteExpiresAt
	}
	session := &models.Session{
		UserID:            old.UserID,
		SessionToken:      newToken,
		UserAgent:         old.UserAgent,
		IPAddress:         old.IPAddress,
		LastSeenAt:        &now,
		ExpiresAt:         &expiresAt,
		AbsoluteExpiresAt: old.AbsoluteExpiresAt,
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	_ = c.storage.DeleteSession(ctx, old.ID)
	return created, nil
}

// ValidateSessionToken looks up a session token, checks expiry, and returns the user and
// their role names. Used by the auth middleware on every authenticated request.
func (c *KeyorixCore) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("session not found")
	}
	if session.ExpiresAt != nil && c.now().After(*session.ExpiresAt) {
		return nil, nil, fmt.Errorf("session expired")
	}
	// Best-effort, throttled last-seen stamp for the My Account sessions view.
	// Only writes when the stored value is older than sessionTouchInterval, so the
	// auth hot path is not turned into a write per request. Never fails the request.
	_ = c.storage.TouchSession(ctx, session.ID, c.now(), sessionTouchInterval)
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

// RequestPasswordReset issues a password-reset link for the given email and
// delivers it via the configured credential-delivery channel (ADR-028). The
// recipient consumes it at /auth/setup/{token} to set a new password
// (completePasswordSetup handles the password_reset_link purpose).
//
// Always returns nil: the outcome must not reveal whether the email maps to an
// account (enumeration-safe), so unknown addresses, suspended accounts, throttled
// repeats, and delivery/config failures are all swallowed. The attempt itself is
// audited inside provisionSetupLink.
func (c *KeyorixCore) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil // Don't reveal whether the email exists.
	}
	// Never send a reset to a login-blocked (e.g. suspended) account.
	if AccountLoginBlocked(user.AccountState) {
		return nil
	}
	// Throttle abusive repeats to a victim address (same control as resend).
	if err := c.checkResendThrottle(ctx, SetupPurposePasswordResetLink, user.Email); err != nil {
		return nil
	}
	_, _ = c.provisionSetupLink(ctx, IssueSetupTokenRequest{
		Purpose:       SetupPurposePasswordResetLink,
		SubjectEmail:  user.Email,
		SubjectUserID: &user.ID,
		CreatedBy:     0, // self-service (no issuing admin)
	}, user.DisplayName, "")
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
