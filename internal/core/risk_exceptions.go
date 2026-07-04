// risk_exceptions.go — the risk register / exceptions (ISO 27001 A.5.8 risk
// treatment / A.5.36 compliance with policies). An exception is a governed,
// time-bound acceptance of a known control gap: a named risk, accepted by an owner
// with a written justification, that sunsets at a fixed date. It turns a raw
// posture violation into a *governed* exception an auditor can see was accepted with
// a deadline, not silently ignored. Effective status (active/expired/revoked) is
// computed at read time from the revoked flag and the expiry.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Effective risk-exception status (computed from revoked + expiry).
const (
	ExceptionStatusActive  = "active"
	ExceptionStatusExpired = "expired"
	ExceptionStatusRevoked = "revoked"

	EventRiskExceptionCreated  = "risk.exception_created"
	EventRiskExceptionRevoked  = "risk.exception_revoked"
	EventRiskExceptionApproved = "risk.exception_approved"
)

// validExceptionCategories are the risk areas an exception may cover (aligned with
// the posture controls so an exception can annotate a specific gap).
var validExceptionCategories = map[string]struct{}{
	"sod": {}, "mfa": {}, "rotation": {}, "dormant_access": {}, "classification": {}, "other": {},
}

// RiskExceptionView is a stored exception plus its effective status at read time.
type RiskExceptionView struct {
	*models.RiskException
	Status string `json:"status"` // active | expired | revoked (computed)
}

// exceptionStatus computes the effective status from the revoked flag and expiry.
func exceptionStatus(e *models.RiskException, now time.Time) string {
	if e.Revoked {
		return ExceptionStatusRevoked
	}
	if !e.ExpiresAt.After(now) {
		return ExceptionStatusExpired
	}
	return ExceptionStatusActive
}

// maxRiskExceptionDuration caps how far out a risk exception may be set to expire — an
// exception must sunset and be re-reviewed, not become a permanent waiver.
const maxRiskExceptionDuration = 365 * 24 * time.Hour

// CreateRiskException records a governed, time-bound acceptance of a control gap.
// actorID is the accepting owner; expiresAt must be in the future. The exception
// does NOT suppress anything yet: it must be separately approved by a DIFFERENT
// system.write holder (see ApproveRiskException) before it takes effect — dual
// control (#170), so the creator can't unilaterally suppress a violation of their
// own. For category "sod", reference should be the matching SoDViolation's
// Reference field (as returned by GET /sod/violations) so the exception, once
// approved, suppresses that one violation specifically.
func (c *KeyorixCore) CreateRiskException(ctx context.Context, actorID uint, title, category, reference, justification string, expiresAt time.Time) (*models.RiskException, error) {
	if title == "" || justification == "" {
		return nil, fmt.Errorf("title and justification are required")
	}
	if _, ok := validExceptionCategories[category]; !ok {
		return nil, fmt.Errorf("category must be one of sod|mfa|rotation|dormant_access|classification|other")
	}
	if !expiresAt.After(c.now()) {
		return nil, fmt.Errorf("expires_at must be in the future (exceptions are time-bound)")
	}
	// A risk exception MUST sunset — bound the duration so it can't be set effectively
	// forever (e.g. year 9999), defeating the "accepted with a sunset" governance intent.
	if expiresAt.After(c.now().Add(maxRiskExceptionDuration)) {
		return nil, fmt.Errorf("expires_at must be within %d days (exceptions must sunset and be re-reviewed)", int(maxRiskExceptionDuration/(24*time.Hour)))
	}
	created, err := c.storage.CreateRiskException(ctx, &models.RiskException{
		Title: title, Category: category, Reference: reference, Justification: justification,
		CreatedBy: actorID, CreatedAt: c.now(), ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, err
	}
	c.writeAuditEvent(ctx, EventRiskExceptionCreated, actorPtr(actorID), nil,
		fmt.Sprintf("risk exception %d accepted: %q (category=%s, ref=%q) until %s",
			created.ID, title, category, reference, expiresAt.UTC().Format(time.RFC3339)))
	return created, nil
}

// listRiskExceptionRows is the one storage read shared by ListRiskExceptions,
// CountExpiredRiskExceptions, and the compliance snapshot's own risk-register
// rollup: every row gets its effective status computed here, so a caller needing a
// different slice of that status (active only, expired only, or every non-revoked
// row) never has to re-query storage to get it (#256, #395).
func (c *KeyorixCore) listRiskExceptionRows(ctx context.Context, activeOnly bool) ([]*RiskExceptionView, error) {
	rows, err := c.storage.ListRiskExceptions(ctx, activeOnly) // activeOnly excludes revoked at storage
	if err != nil {
		return nil, err
	}
	now := c.now()
	out := make([]*RiskExceptionView, 0, len(rows))
	for _, e := range rows {
		out = append(out, &RiskExceptionView{RiskException: e, Status: exceptionStatus(e, now)})
	}
	return out, nil
}

// ListRiskExceptions returns exceptions with their effective status. When activeOnly
// is set, only currently-active (not revoked, not expired) exceptions are returned;
// otherwise every non-revoked exception is returned (expired included, for history).
func (c *KeyorixCore) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*RiskExceptionView, error) {
	views, err := c.listRiskExceptionRows(ctx, activeOnly)
	if err != nil {
		return nil, err
	}
	if !activeOnly {
		return views, nil
	}
	out := make([]*RiskExceptionView, 0, len(views))
	for _, v := range views {
		if v.Status == ExceptionStatusActive {
			out = append(out, v) // storage dropped revoked; drop expired here too
		}
	}
	return out, nil
}

// CountExpiredRiskExceptions returns how many stored risk exceptions have passed
// their expiry but are still marked non-revoked — i.e. a governed acceptance whose
// sunset came and went with no renewal or explicit revocation (#395). The risk it
// was excepting is unmitigated again the moment expiry passes, but without this
// count the compliance matrix has no visibility into that: the exception simply
// drops out of the "active" tally (see ListRiskExceptions/CountActiveRiskExceptions)
// as if it had never existed, rather than surfacing as a stale acceptance an
// auditor needs to see.
func (c *KeyorixCore) CountExpiredRiskExceptions(ctx context.Context) (int, error) {
	views, err := c.listRiskExceptionRows(ctx, true) // excludes revoked; expiry computed here
	if err != nil {
		return 0, err
	}
	expired := 0
	for _, v := range views {
		if v.Status == ExceptionStatusExpired {
			expired++
		}
	}
	return expired, nil
}

// RevokeRiskException withdraws an exception before its expiry. actorID is the admin.
func (c *KeyorixCore) RevokeRiskException(ctx context.Context, actorID, id uint) error {
	e, err := c.storage.GetRiskException(ctx, id)
	if err != nil {
		return err
	}
	if e.Revoked {
		return fmt.Errorf("risk exception %d is already revoked", id)
	}
	now := c.now()
	e.Revoked = true
	e.RevokedBy = actorID
	e.RevokedAt = &now
	if err := c.storage.UpdateRiskException(ctx, e); err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventRiskExceptionRevoked, actorPtr(actorID), nil,
		fmt.Sprintf("risk exception %d revoked: %q", id, e.Title))
	return nil
}

// ApproveRiskException dual-controls an exception (#170): actorID must be a
// DIFFERENT principal than the one who created it. Only an approved, still-active
// exception suppresses its matched violation from the compliance posture — before
// approval the raw violation keeps counting, so a self-dealt exception has no
// effect. A denied self-approval attempt is itself audited distinctly from a grant.
func (c *KeyorixCore) ApproveRiskException(ctx context.Context, actorID, id uint) error {
	e, err := c.storage.GetRiskException(ctx, id)
	if err != nil {
		return err
	}
	if e.Revoked {
		return fmt.Errorf("cannot approve a revoked risk exception")
	}
	if exceptionStatus(e, c.now()) == ExceptionStatusExpired {
		return fmt.Errorf("cannot approve an expired risk exception")
	}
	if e.Approved {
		return fmt.Errorf("risk exception %d is already approved", id)
	}
	if actorID == e.CreatedBy {
		c.writeAuditEventFailed(ctx, EventRiskExceptionApproved, actorPtr(actorID), "",
			fmt.Sprintf("risk exception %d approval DENIED: creator %d cannot self-approve", id, actorID))
		return fmt.Errorf("the exception's creator cannot approve it (dual control); a different system.write holder must approve")
	}
	now := c.now()
	e.Approved = true
	e.ApprovedBy = actorID
	e.ApprovedAt = &now
	if err := c.storage.UpdateRiskException(ctx, e); err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventRiskExceptionApproved, actorPtr(actorID), nil,
		fmt.Sprintf("risk exception %d approved by %d (created by %d): %q", id, actorID, e.CreatedBy, e.Title))
	return nil
}

// CountActiveRiskExceptions returns how many exceptions are currently active and how
// many of those expire within the `soon` window — for the compliance posture.
func (c *KeyorixCore) CountActiveRiskExceptions(ctx context.Context, soon time.Duration) (active, expiringSoon int, err error) {
	rows, err := c.storage.ListRiskExceptions(ctx, true)
	if err != nil {
		return 0, 0, err
	}
	now := c.now()
	cutoff := now.Add(soon)
	for _, e := range rows {
		if exceptionStatus(e, now) != ExceptionStatusActive {
			continue
		}
		active++
		if e.ExpiresAt.Before(cutoff) {
			expiringSoon++
		}
	}
	return active, expiringSoon, nil
}
