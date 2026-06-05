// setup_token.go — credential-delivery setup tokens (ADR-028).
//
// A setup token is the single-use bearer string that lets a brand-new principal
// establish their first credential. It backs three producers — invitation
// acceptance (ADR-024), admin-direct account setup (ADR-025), and the reset-link
// path — selected by Purpose. The raw token is returned once on issuance (to embed
// in an https link or display out of band) and never persisted; only its SHA-256
// hash is stored, and lookup is by hash. This mirrors the PAT handling in pat.go.
//
// Lifecycle invariants:
//   - Single-use: consuming flips active → consumed via a state-guarded UPDATE, so a
//     replay matches zero rows and is rejected.
//   - Short TTL: default 24h (configurable). A lazy-expire check flips an overdue
//     active token to expired on read.
//   - Superseded on reissue: minting a new token for the same (purpose, email)
//     supersedes any prior active one, so "resend" kills the old link instantly.
//   - Purpose-scoped: a token minted for one purpose can never drive another.
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Setup-token purposes. A token is bound to exactly one at issuance.
const (
	SetupPurposeInvitationAccept  = "invitation_accept"
	SetupPurposeAccountSetup      = "account_setup"
	SetupPurposePasswordResetLink = "password_reset_link"
)

// Setup-token states.
const (
	SetupTokenActive     = "active"
	SetupTokenConsumed   = "consumed"
	SetupTokenExpired    = "expired"
	SetupTokenSuperseded = "superseded"
)

const (
	// setupPrefix marks a raw setup token. Load-bearing for secret-scanning leak
	// detection; the token travels in an https link, not the auth bearer path.
	setupPrefix = "kx_setup_"
	// DefaultSetupTokenTTL is the fallback link lifetime when none is configured.
	DefaultSetupTokenTTL = 24 * time.Hour
)

// validSetupPurpose reports whether p is a recognised purpose.
func validSetupPurpose(p string) bool {
	switch p {
	case SetupPurposeInvitationAccept, SetupPurposeAccountSetup, SetupPurposePasswordResetLink:
		return true
	default:
		return false
	}
}

// hashSetupToken returns the SHA-256 hex of a raw token — the stored, indexed form.
func hashSetupToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// IssueSetupTokenRequest describes a token to mint.
type IssueSetupTokenRequest struct {
	Purpose       string
	SubjectEmail  string // the address the token is bound to (required)
	SubjectUserID *uint  // nil until an account exists (e.g. invitation by email)
	InvitationID  *uint  // set for purpose = invitation_accept
	CreatedBy     uint   // issuing admin/inviter; 0 for self-service reset
}

// IssueSetupTokenResult carries the freshly minted token plus its one-time plaintext.
// PlainToken is never persisted and never returned again.
type IssueSetupTokenResult struct {
	Token      *models.SetupToken
	PlainToken string
}

// IssueSetupToken mints a single-use setup token, superseding any prior active token
// for the same (purpose, email) so a reissue invalidates the old link. The raw token
// is returned once; only its hash is stored.
func (c *KeyorixCore) IssueSetupToken(ctx context.Context, req IssueSetupTokenRequest) (*IssueSetupTokenResult, error) {
	if !validSetupPurpose(req.Purpose) {
		return nil, fmt.Errorf("%s: unknown setup-token purpose %q", i18n.T("ErrorValidation", nil), req.Purpose)
	}
	email := strings.TrimSpace(strings.ToLower(req.SubjectEmail))
	if email == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "subject email is required")
	}

	// Supersede any prior active token for this subject+purpose first, so the old
	// link dies the instant the new one is issued (safe "resend").
	if err := c.storage.SupersedeActiveSetupTokens(ctx, req.Purpose, email); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	raw := setupPrefix + base64.RawURLEncoding.EncodeToString(b)

	ttl := c.setupTokenTTL
	if ttl <= 0 {
		ttl = DefaultSetupTokenTTL
	}
	now := c.now()

	tok := &models.SetupToken{
		TokenHash:     hashSetupToken(raw),
		Purpose:       req.Purpose,
		SubjectUserID: req.SubjectUserID,
		SubjectEmail:  email,
		InvitationID:  req.InvitationID,
		State:         SetupTokenActive,
		ExpiresAt:     now.Add(ttl),
		CreatedBy:     req.CreatedBy,
		CreatedAt:     now,
	}
	created, err := c.storage.CreateSetupToken(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Issuer is the actor; for self-service reset (CreatedBy == 0) attribute to the
	// subject. No token (not even the hash) is recorded on the audit row.
	actor := actorOrSubject(req.CreatedBy, req.SubjectUserID)
	c.writeAuditEventFull(ctx, "setup_token.issued", actor, nil, nil, "",
		fmt.Sprintf("setup token issued (purpose=%s, subject=%s, expires=%s)",
			req.Purpose, email, created.ExpiresAt.Format(time.RFC3339)))

	return &IssueSetupTokenResult{Token: created, PlainToken: raw}, nil
}

// ValidateSetupToken resolves a raw token to its record for the expected purpose,
// without consuming it (the landing page calls this to show the assignment summary).
// It rejects unknown, non-active, wrong-purpose, and expired tokens, lazily flipping
// an overdue active token to expired as a side effect.
func (c *KeyorixCore) ValidateSetupToken(ctx context.Context, raw, expectedPurpose string) (*models.SetupToken, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	// Purpose-scoping: the token may only drive the flow it was minted for.
	if tok.Purpose != expectedPurpose {
		return nil, fmt.Errorf("%s: setup token purpose mismatch", i18n.T("ErrorValidation", nil))
	}
	return tok, nil
}

// inspectActiveSetupToken resolves a raw token, lazily expires it if overdue, and
// returns it only if active. It does NOT check purpose — callers that know the
// expected purpose use ValidateSetupToken; the GET-describe path (which must report
// the purpose to the landing page) uses this directly.
func (c *KeyorixCore) inspectActiveSetupToken(ctx context.Context, raw string) (*models.SetupToken, error) {
	tok, err := c.storage.GetSetupTokenByHash(ctx, hashSetupToken(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid setup token", i18n.T("ErrorNotFound", nil))
	}

	// Lazy expiry: an active token past its TTL is flipped to expired on read.
	if tok.State == SetupTokenActive && c.now().After(tok.ExpiresAt) {
		_ = c.storage.MarkSetupTokenExpired(ctx, tok.ID)
		c.writeAuditEventFull(ctx, "setup_token.expired", tok.SubjectUserID, nil, nil, "",
			fmt.Sprintf("setup token expired (purpose=%s, subject=%s)", tok.Purpose, tok.SubjectEmail))
		return nil, fmt.Errorf("%s: setup token expired", i18n.T("ErrorNotFound", nil))
	}
	if tok.State != SetupTokenActive {
		return nil, fmt.Errorf("%s: setup token is %s", i18n.T("ErrorNotFound", nil), tok.State)
	}
	return tok, nil
}

// ConsumeSetupToken validates a token for the expected purpose and atomically marks
// it consumed (single-use). The returned record lets the caller materialize the
// token's effect (accept the invitation / set the password). Consumption is burned
// up front: if the caller's subsequent materialization fails, the token is already
// spent — a deliberate fail-closed choice, since a setup token is a credential.
func (c *KeyorixCore) ConsumeSetupToken(ctx context.Context, raw, expectedPurpose string) (*models.SetupToken, error) {
	tok, err := c.ValidateSetupToken(ctx, raw, expectedPurpose)
	if err != nil {
		return nil, err
	}
	ok, err := c.storage.MarkSetupTokenConsumed(ctx, tok.ID, c.now())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !ok {
		// Lost a race to a concurrent consumer (or already spent between validate
		// and mark). Single-use holds: reject.
		return nil, fmt.Errorf("%s: setup token already used", i18n.T("ErrorNotFound", nil))
	}
	c.writeAuditEventFull(ctx, "setup_token.consumed", tok.SubjectUserID, nil, nil, "",
		fmt.Sprintf("setup token consumed (purpose=%s, subject=%s)", tok.Purpose, tok.SubjectEmail))
	return tok, nil
}

// actorOrSubject returns the issuing admin as the audit actor, falling back to the
// subject for self-service issuance (createdBy == 0).
func actorOrSubject(createdBy uint, subjectUserID *uint) *uint {
	if createdBy != 0 {
		a := createdBy
		return &a
	}
	return subjectUserID
}
