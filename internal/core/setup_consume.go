// setup_consume.go — public consumption of credential-delivery setup tokens (ADR-028).
//
// These power the unauthenticated landing page a new principal reaches via their
// setup link: a GET that describes the token (no secrets) so the page can render the
// right form, and the consume that sets the password and lands the user logged in.
//
// The password-setting purposes (account_setup, password_reset_link) act on an
// existing account; invitation_accept lazily creates the invited account and
// materializes its project membership (ADR-024). Each is dispatched by purpose.
package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrInvalidSetupPassword wraps a password-policy rejection during setup-token
// consume. It is the ONLY consume failure whose reason is safe (and useful) to
// surface to the unauthenticated caller — the link stays live so they can retry.
// Every other failure (dead token, missing/duplicate account, internal error) is
// reported generically by the HTTP layer so the public endpoint is not an
// account-existence / error-string oracle.
var ErrInvalidSetupPassword = errors.New("invalid password")

// SetupTokenInfo is the non-sensitive description of a setup token returned to the
// landing page. It deliberately carries no token, no hash, and no secret material.
type SetupTokenInfo struct {
	Purpose     string `json:"purpose"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
}

// SetupConsumeResult is returned after a setup token is consumed: the freshly minted
// session (auto-login) plus the user it belongs to, so the HTTP layer can build a
// login-shaped response.
type SetupConsumeResult struct {
	Session *models.Session
	User    *models.User
}

// DescribeSetupToken validates a raw setup token (without consuming it) and returns
// a non-sensitive description for the landing page, or an error if the token is
// unknown, expired, or otherwise not active. It is the GET /auth/setup/{token} path.
func (c *KeyorixCore) DescribeSetupToken(ctx context.Context, raw string) (*SetupTokenInfo, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	info := &SetupTokenInfo{Purpose: tok.Purpose, Email: tok.SubjectEmail}
	// Resolve a friendly name when the account already exists (best-effort; never
	// leaks more than the display name the user set).
	if tok.SubjectUserID != nil {
		if u, uerr := c.storage.GetUser(ctx, *tok.SubjectUserID); uerr == nil {
			info.DisplayName = u.DisplayName
		}
	}
	return info, nil
}

// CompleteSetup consumes a setup token and materializes its effect. For the
// account_setup and password_reset_link purposes it: validates the new password
// BEFORE spending the token (a weak password must not burn the link), atomically
// consumes the token, sets the password (clearing the account back to active), and
// mints a login session so the user lands authenticated. The invitation_accept
// purpose is completed by the invitation producer, not here.
func (c *KeyorixCore) CompleteSetup(ctx context.Context, raw, newPassword, userAgent, ip string) (*SetupConsumeResult, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	switch tok.Purpose {
	case SetupPurposeAccountSetup, SetupPurposePasswordResetLink:
		return c.completePasswordSetup(ctx, raw, tok, newPassword, userAgent, ip)
	case SetupPurposeInvitationAccept:
		return c.completeInvitationAccept(ctx, raw, tok, newPassword, userAgent, ip)
	default:
		return nil, fmt.Errorf("%s: setup token purpose %q is not completed at this endpoint", i18n.T("ErrorValidation", nil), tok.Purpose)
	}
}

// completePasswordSetup handles account_setup / password_reset_link: set the existing
// subject's password and auto-log them in.
func (c *KeyorixCore) completePasswordSetup(ctx context.Context, raw string, tok *models.SetupToken, newPassword, userAgent, ip string) (*SetupConsumeResult, error) {
	if tok.SubjectUserID == nil {
		return nil, fmt.Errorf("%s: setup token has no subject account", i18n.T("ErrorValidation", nil))
	}
	user, err := c.storage.GetUser(ctx, *tok.SubjectUserID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	// A suspended account cannot be activated via a setup link.
	if AccountLoginBlocked(user.AccountState) {
		return nil, fmt.Errorf("account suspended")
	}

	// Validate the password BEFORE consuming the token, so a policy rejection lets
	// the user retry with the same link instead of dead-ending on a spent token.
	if err := c.validateNewPassword(ctx, user, newPassword); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSetupPassword, err)
	}

	// Consume is single-use and atomic; from here the token is spent (fail-closed).
	if _, err := c.ConsumeSetupToken(ctx, raw, tok.Purpose); err != nil {
		return nil, err
	}
	if err := c.applyNewPassword(ctx, user, newPassword); err != nil {
		return nil, err
	}

	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	c.writeAuditEventFull(ctx, "account.setup_completed", &user.ID, nil, nil, ip,
		fmt.Sprintf("account setup completed via %s", tok.Purpose))

	return &SetupConsumeResult{Session: session, User: user}, nil
}

// completeInvitationAccept handles invitation_accept: lazily create the invited
// account (ADR-024/ADR-028), accept the invitation, create a project membership
// honouring the validation mode snapshotted at invite time (which grants the role
// when the mode lands it active), and auto-log the user in.
func (c *KeyorixCore) completeInvitationAccept(ctx context.Context, raw string, tok *models.SetupToken, newPassword, userAgent, ip string) (*SetupConsumeResult, error) {
	if tok.InvitationID == nil {
		return nil, fmt.Errorf("%s: invitation token has no invitation", i18n.T("ErrorValidation", nil))
	}
	inv, err := c.storage.GetProjectInvitation(ctx, *tok.InvitationID)
	if err != nil {
		return nil, fmt.Errorf("%s: invitation not found", i18n.T("ErrorNotFound", nil))
	}
	// Lazy-expire an overdue invite, then require it still be pending.
	if inv.State == InvitationPending && inv.ExpiresAt != nil && c.now().After(*inv.ExpiresAt) {
		inv.State = InvitationExpired
		_ = c.storage.UpdateProjectInvitation(ctx, inv)
	}
	if inv.State != InvitationPending {
		return nil, fmt.Errorf("%s: invitation is %s", i18n.T("ErrorValidation", nil), inv.State)
	}

	// SECURITY: if an account already exists for this email, the invite link must NOT
	// log them in — that would bypass their real password. Reject and route them to
	// the normal add-member flow instead of auto-authenticating.
	if existing, eerr := c.storage.GetUserByEmail(ctx, inv.Email); eerr == nil && existing != nil {
		return nil, fmt.Errorf("%s: an account already exists for %s; ask an admin to add you to the project directly", i18n.T("ErrorValidation", nil), inv.Email)
	}

	// Validate the password before consuming (a weak password must not burn the link).
	// No account exists yet, so this is policy-only (no history to check).
	if err := c.passwordPolicy.Validate(newPassword, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Consume the token (single-use, atomic) before materializing.
	if _, err := c.ConsumeSetupToken(ctx, raw, SetupPurposeInvitationAccept); err != nil {
		return nil, err
	}

	// Lazily create the account with the chosen password (active — they just set it).
	username, err := c.deriveUsername(ctx, inv.Email)
	if err != nil {
		return nil, err
	}
	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username:    username,
		Email:       inv.Email,
		DisplayName: displayNameFromEmail(inv.Email),
		Password:    newPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Mark the invitation accepted.
	now := c.now()
	inv.State = InvitationAccepted
	inv.AcceptedAt = &now
	_ = c.storage.UpdateProjectInvitation(ctx, inv)

	// Create the membership under the invite-time validation mode. This grants the
	// project role immediately when the mode (e.g. open) lands it active; under
	// allowlist it starts in `invited` for an admin to advance.
	if _, err := c.inviteMemberWithMode(ctx, inv.ProjectID, user.ID, inv.Role, inv.InvitedBy, inv.ValidationModeAtInvite, false); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	c.auditProjectScoped(ctx, "invitation.accepted", user.ID, inv.ProjectID,
		fmt.Sprintf("invitation %d accepted by %s (user %d)", inv.ID, inv.Email, user.ID))

	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return &SetupConsumeResult{Session: session, User: user}, nil
}

// deriveUsername builds a unique, alphanumeric username from an email's local part,
// appending a numeric suffix on collision. Best-effort: CreateUser re-checks
// uniqueness, so a racy lookup at worst surfaces there.
func (c *KeyorixCore) deriveUsername(ctx context.Context, email string) (string, error) {
	base := sanitizeUsername(localPart(email))
	if len(base) < 3 {
		base += "user"
	}
	candidate := base
	for i := 1; i <= 1000; i++ {
		if _, err := c.storage.GetUserByUsername(ctx, candidate); err != nil {
			return candidate, nil // not found → available
		}
		candidate = fmt.Sprintf("%s%d", base, i)
	}
	return "", fmt.Errorf("%s: could not derive a unique username for %s", i18n.T("ErrorValidation", nil), email)
}

// localPart returns the part of an email before '@' (or the whole string if none).
func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// sanitizeUsername lowercases and keeps only [a-z0-9].
func sanitizeUsername(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// displayNameFromEmail derives a human-facing default name from an email.
func displayNameFromEmail(email string) string {
	if lp := localPart(email); lp != "" {
		return lp
	}
	return email
}
