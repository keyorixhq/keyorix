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

	EventRiskExceptionCreated = "risk.exception_created"
	EventRiskExceptionRevoked = "risk.exception_revoked"
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

// CreateRiskException records a governed, time-bound acceptance of a control gap.
// actorID is the accepting owner; expiresAt must be in the future.
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

// ListRiskExceptions returns exceptions with their effective status. When activeOnly
// is set, only currently-active (not revoked, not expired) exceptions are returned;
// otherwise every non-revoked exception is returned (expired included, for history).
func (c *KeyorixCore) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*RiskExceptionView, error) {
	rows, err := c.storage.ListRiskExceptions(ctx, activeOnly) // activeOnly excludes revoked at storage
	if err != nil {
		return nil, err
	}
	now := c.now()
	out := make([]*RiskExceptionView, 0, len(rows))
	for _, e := range rows {
		st := exceptionStatus(e, now)
		if activeOnly && st != ExceptionStatusActive {
			continue // storage dropped revoked; drop expired here too
		}
		out = append(out, &RiskExceptionView{RiskException: e, Status: st})
	}
	return out, nil
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
