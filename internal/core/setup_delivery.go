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
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrSetupBaseURLRequired is returned when a setup link is requested but
// credential_delivery.base_url is unconfigured. It is a misconfiguration (a relative
// link is never a fallback), so the HTTP layer maps it to a 400 with this reason
// rather than a generic 500 — letting an admin fix the config.
var ErrSetupBaseURLRequired = errors.New("credential_delivery.base_url is required to issue a setup link")

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
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrSetupBaseURLRequired)
	}
	issued, err := c.IssueSetupToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return c.deliverSetupLink(ctx, issued, req, displayName, assignmentSummary)
}

// provisionSetupLinkThrottled is provisionSetupLink with the per-subject resend
// throttle (ADR-028 abuse section) applied atomically. The throttle check counts
// recent tokens and then a new token is minted; without serialization two concurrent
// resends for the same (purpose, email) both see a sub-cap count and both mint,
// exceeding the daily cap / min-interval (the count-then-act is the only way past
// the cap, so the race defeats the sole mail-bombing control). setupResendMu is held
// across the check + IssueSetupToken so the count and the write that the next count
// will see are one critical section. Delivery runs after the lock is released — a
// slow SMTP send must not block every other resend. Used by every resend path; the
// initial-provision callers (new account / new invitation) start from a zero count
// and call provisionSetupLink directly.
func (c *KeyorixCore) provisionSetupLinkThrottled(ctx context.Context, req IssueSetupTokenRequest, displayName, assignmentSummary string) (*ProvisionSetupResult, error) {
	if c.setupBaseURL == "" {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrSetupBaseURLRequired)
	}
	c.setupResendMu.Lock()
	if err := c.checkResendThrottle(ctx, req.Purpose, req.SubjectEmail); err != nil {
		c.setupResendMu.Unlock()
		return nil, err
	}
	issued, err := c.IssueSetupToken(ctx, req)
	c.setupResendMu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.deliverSetupLink(ctx, issued, req, displayName, assignmentSummary)
}

// deliverSetupLink builds the absolute setup link from a freshly issued token and
// delivers it via the configured channel (or hands it back out-of-band), auditing
// the delivery. Split from provisionSetupLink so the slow delivery step runs outside
// the resend-throttle lock.
func (c *KeyorixCore) deliverSetupLink(ctx context.Context, issued *IssueSetupTokenResult, req IssueSetupTokenRequest, displayName, assignmentSummary string) (*ProvisionSetupResult, error) {
	link := c.setupBaseURL + "/auth/setup/" + issued.PlainToken

	var result delivery.DeliveryResult
	if c.credentialDelivery != nil {
		var err error
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
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrSetupBaseURLRequired)
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

// OneTimePasswordResult carries the out-of-band one-time password for the admin to
// relay (ADR-028 Part E). It is returned once, at creation, and never stored in clear:
// only the bcrypt hash is persisted, and the account is forced into
// password_reset_required so the user must replace it on first login.
type OneTimePasswordResult struct {
	Email           string `json:"email"`
	OneTimePassword string `json:"one_time_password"`
}

// CreateUserWithOneTimePassword creates a user with a server-generated initial password
// and forces it into password_reset_required (ADR-025), returning the password once for
// the admin to relay out-of-band (ADR-028 Part E). It is the alternative to the
// setup-link path for when an admin wants to set an initial credential rather than have
// the end user choose one: the admin holds the first credential, so the account must
// change it on first login. The password is never emailed and never persisted in clear
// (only its bcrypt hash). No base URL is required — there is no link.
func (c *KeyorixCore) CreateUserWithOneTimePassword(ctx context.Context, req *CreateUserRequest, createdBy uint) (*models.User, *OneTimePasswordResult, error) {
	otp, err := generateOneTimePassword()
	if err != nil {
		return nil, nil, err
	}

	// Create the account directly in password_reset_required with the generated
	// password, in the SAME write — no second UpdateUser that, on failure, could
	// strand an active account whose credential the admin already saw.
	reqCopy := *req
	reqCopy.Password = otp
	reqCopy.AccountState = AccountPasswordResetRequired
	user, err := c.CreateUser(ctx, &reqCopy)
	if err != nil {
		return nil, nil, err
	}

	// Record that a human saw a credential — the one path the ADR singles out for
	// compliance (artifact=one_time_password, vs the setup-link artifact).
	actor := actorOrSubject(createdBy, &user.ID)
	c.writeAuditEventFull(ctx, "credential.displayed_out_of_band", actor, nil, nil, "",
		fmt.Sprintf("one-time password shown out-of-band to admin (subject=%s, artifact=one_time_password)", user.Email))

	return user, &OneTimePasswordResult{Email: user.Email, OneTimePassword: otp}, nil
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
	return c.provisionSetupLinkThrottled(ctx, IssueSetupTokenRequest{
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

// One-time-password character classes (ADR-028 Part E). Visually ambiguous characters
// (0/O, 1/l/I) are excluded so the password survives being read aloud or copied by hand
// when the admin relays it out of band.
const (
	otpLower   = "abcdefghijkmnpqrstuvwxyz" // no l, o
	otpUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O
	otpDigits  = "23456789"                 // no 0, 1
	otpSpecial = "!@#$%^&*-_=+"
	otpLength  = 20
)

// generateOneTimePassword returns a high-entropy password that satisfies the default
// ADR-025 password policy (length + all four character classes). It seeds one character
// from each required class so the policy always holds regardless of the random draw,
// fills the rest from the union, then shuffles so the seeded characters aren't in fixed
// positions. All randomness is from crypto/rand.
func generateOneTimePassword() (string, error) {
	classes := []string{otpLower, otpUpper, otpDigits, otpSpecial}
	all := otpLower + otpUpper + otpDigits + otpSpecial

	out := make([]byte, otpLength)
	for i, class := range classes {
		ch, err := randChar(class)
		if err != nil {
			return "", err
		}
		out[i] = ch
	}
	for i := len(classes); i < otpLength; i++ {
		ch, err := randChar(all)
		if err != nil {
			return "", err
		}
		out[i] = ch
	}
	if err := shuffleBytes(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// randChar returns a uniformly random byte from set using crypto/rand.
func randChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return set[n.Int64()], nil
}

// shuffleBytes performs an in-place Fisher–Yates shuffle using crypto/rand, so the
// class-seeded characters do not stay in their initial positions.
func shuffleBytes(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		jj := int(j.Int64())
		b[i], b[jj] = b[jj], b[i]
	}
	return nil
}
