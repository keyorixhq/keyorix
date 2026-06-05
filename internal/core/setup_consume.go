// setup_consume.go — public consumption of credential-delivery setup tokens (ADR-028).
//
// These power the unauthenticated landing page a new principal reaches via their
// setup link: a GET that describes the token (no secrets) so the page can render the
// right form, and the consume that sets the password and lands the user logged in.
//
// Only the password-setting purposes (account_setup, password_reset_link) are
// completed here — both act on an existing account. The invitation_accept purpose,
// which must also materialize project membership, is completed by the invitation
// producer (ADR-024) and is rejected here.
package core

import (
	"context"
	"errors"
	"fmt"

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
		// handled below
	default:
		return nil, fmt.Errorf("%s: setup token purpose %q is not completed at this endpoint", i18n.T("ErrorValidation", nil), tok.Purpose)
	}
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
