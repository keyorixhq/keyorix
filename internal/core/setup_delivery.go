// setup_delivery.go — credential-delivery producers (ADR-028).
//
// These turn the setup-token primitive + delivery channel into the admin-facing
// flows: provisioning a brand-new account's first-credential link, and resending it.
// A producer issues a token, builds the absolute setup link, delivers it via the
// configured channel, and audits the delivery. In out-of-band mode the link is
// returned to the admin to relay; that display is itself audited
// (credential.displayed_out_of_band) because a human briefly sees a credential.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Resend throttling (ADR-028 abuse section): a minimum interval between issues for
// the same subject, and a daily cap, both per (purpose, email).
const (
	resendMinInterval = 60 * time.Second
	resendDailyCap    = 10
)

// SetCredentialDelivery wires the credential-delivery channel and the base URL used
// to build absolute setup links (ADR-028). The server/CLI calls this at startup from
// the credential_delivery config. A nil deliverer means out-of-band: the link is
// returned to the caller rather than sent.
func (c *KeyorixCore) SetCredentialDelivery(d delivery.CredentialDelivery, baseURL string) {
	c.credentialDelivery = d
	c.setupBaseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

// ProvisionSetupResult reports how a setup link was provisioned and delivered.
type ProvisionSetupResult struct {
	Email        string `json:"email"`
	Channel      string `json:"channel"`                  // smtp | out_of_band | log
	Delivered    bool   `json:"delivered"`                // true if actually sent
	LinkForAdmin string `json:"link_for_admin,omitempty"` // set in out-of-band mode
}

// provisionSetupLink issues a setup token for the request's subject and delivers it
// via the configured channel, returning the outcome. Requires a configured base URL
// (a relative link is a misconfiguration, not a fallback).
func (c *KeyorixCore) provisionSetupLink(ctx context.Context, req IssueSetupTokenRequest, displayName, assignmentSummary string) (*ProvisionSetupResult, error) {
	if c.setupBaseURL == "" {
		return nil, fmt.Errorf("%s: credential_delivery.base_url is required to issue a setup link", i18n.T("ErrorValidation", nil))
	}
	issued, err := c.IssueSetupToken(ctx, req)
	if err != nil {
		return nil, err
	}
	link := c.setupBaseURL + "/auth/setup/" + issued.PlainToken

	var result delivery.DeliveryResult
	if c.credentialDelivery != nil {
		result, err = c.credentialDelivery.DeliverSetupLink(ctx, delivery.SetupLinkRequest{
			RecipientEmail:    req.SubjectEmail,
			DisplayName:       displayName,
			Link:              link,
			Purpose:           req.Purpose,
			AssignmentSummary: assignmentSummary,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	} else {
		// No channel configured → out-of-band: hand the link back to the caller.
		result = delivery.DeliveryResult{Channel: delivery.ChannelOutOfBand, Delivered: false, LinkForAdmin: link}
	}

	// Audit the delivery (no token on the row).
	actor := actorOrSubject(req.CreatedBy, req.SubjectUserID)
	c.writeAuditEventFull(ctx, "setup_link.delivered", actor, nil, nil, "",
		fmt.Sprintf("setup link delivered (purpose=%s, subject=%s, channel=%s, delivered=%t)",
			req.Purpose, req.SubjectEmail, result.Channel, result.Delivered))
	// When the link is shown to the admin out of band, record that a human saw a
	// credential — the one path the ADR singles out for compliance.
	if result.LinkForAdmin != "" {
		c.writeAuditEventFull(ctx, "credential.displayed_out_of_band", actor, nil, nil, "",
			fmt.Sprintf("setup link shown out-of-band to admin (subject=%s, artifact=link)", req.SubjectEmail))
	}

	return &ProvisionSetupResult{
		Email:        req.SubjectEmail,
		Channel:      result.Channel,
		Delivered:    result.Delivered,
		LinkForAdmin: result.LinkForAdmin,
	}, nil
}

// CreateUserWithSetupLink creates a user in pending_first_login state with NO usable
// password and provisions an account_setup link, so the user sets their own password
// via the link instead of the admin choosing one (ADR-025 / ADR-028). Returns the
// created user and the delivery outcome (the link to relay in out-of-band mode).
func (c *KeyorixCore) CreateUserWithSetupLink(ctx context.Context, req *CreateUserRequest, createdBy uint) (*models.User, *ProvisionSetupResult, error) {
	if c.setupBaseURL == "" {
		return nil, nil, fmt.Errorf("%s: credential_delivery.base_url is required to issue a setup link", i18n.T("ErrorValidation", nil))
	}

	// Create the account with a random, unusable password and confined directly to
	// pending_first_login in the SAME write — no second UpdateUser that, on failure,
	// could strand an active account with a password nobody knows. The real password
	// is set when the user consumes the setup link.
	reqCopy := *req
	unusable, err := randomUnusablePassword()
	if err != nil {
		return nil, nil, err
	}
	reqCopy.Password = unusable
	reqCopy.AccountState = AccountPendingFirstLogin
	user, err := c.CreateUser(ctx, &reqCopy)
	if err != nil {
		return nil, nil, err
	}

	res, err := c.provisionSetupLink(ctx, IssueSetupTokenRequest{
		Purpose:       SetupPurposeAccountSetup,
		SubjectEmail:  user.Email,
		SubjectUserID: &user.ID,
		CreatedBy:     createdBy,
	}, user.DisplayName, "")
	if err != nil {
		// The account exists but the link could not be provisioned; surface the user
		// so the caller can resend rather than orphaning a half-created account.
		return user, nil, err
	}
	return user, res, nil
}

// ResendAccountSetupLink reissues an account_setup link for an existing user,
// superseding the prior active token, and re-delivers it. Throttled per ADR-028.
func (c *KeyorixCore) ResendAccountSetupLink(ctx context.Context, userID, createdBy uint) (*ProvisionSetupResult, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if AccountLoginBlocked(user.AccountState) {
		return nil, fmt.Errorf("account suspended")
	}
	if err := c.checkResendThrottle(ctx, SetupPurposeAccountSetup, user.Email); err != nil {
		return nil, err
	}
	return c.provisionSetupLink(ctx, IssueSetupTokenRequest{
		Purpose:       SetupPurposeAccountSetup,
		SubjectEmail:  user.Email,
		SubjectUserID: &user.ID,
		CreatedBy:     createdBy,
	}, user.DisplayName, "")
}

// checkResendThrottle enforces the per-subject resend limits: a minimum interval
// between issues and a daily cap (ADR-028 abuse section). Counting failures fail
// open — a throttle-store error must not block a legitimate resend.
func (c *KeyorixCore) checkResendThrottle(ctx context.Context, purpose, email string) error {
	key := strings.TrimSpace(strings.ToLower(email))

	// Fail CLOSED on a count error: an abuse control that silently no-ops whenever
	// the store hiccups isn't a control. A transient error briefly delays a
	// legitimate resend (acceptable); it must never open the door to unthrottled
	// setup-link mail to a victim address.
	n, err := c.storage.CountSetupTokensSince(ctx, purpose, key, c.now().Add(-24*time.Hour))
	if err != nil {
		return fmt.Errorf("%s: could not verify resend limits, please try again", i18n.T("ErrorValidation", nil))
	}
	if n >= resendDailyCap {
		return fmt.Errorf("%s: resend limit reached (max %d per day)", i18n.T("ErrorValidation", nil), resendDailyCap)
	}
	m, err := c.storage.CountSetupTokensSince(ctx, purpose, key, c.now().Add(-resendMinInterval))
	if err != nil {
		return fmt.Errorf("%s: could not verify resend limits, please try again", i18n.T("ErrorValidation", nil))
	}
	if m >= 1 {
		return fmt.Errorf("%s: please wait before requesting another setup link", i18n.T("ErrorValidation", nil))
	}
	return nil
}

// randomUnusablePassword returns a high-entropy random string used as the initial
// password of a setup-link account. It is never disclosed, so no one can log in
// until the user sets a real password via the link.
func randomUnusablePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
