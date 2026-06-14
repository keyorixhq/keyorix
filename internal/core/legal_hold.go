// legal_hold.go — deployment-wide legal hold (ISO 27001 A.5.34 / eDiscovery / DORA
// record-keeping). While a hold is active the background purge/retention jobs are
// blocked from hard-deleting records (the schedulers call IsLegalHoldActive each
// tick), so data subject to litigation or investigation is preserved. Placing and
// lifting a hold are audited; the row history is the evidence of when holds applied.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Legal-hold audit event types.
const (
	EventLegalHoldPlaced = "data.legal_hold_placed"
	EventLegalHoldLifted = "data.legal_hold_lifted"
)

// GetActiveLegalHold returns the current active hold, or (nil, nil) when none.
func (c *KeyorixCore) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	return c.storage.GetActiveLegalHold(ctx)
}

// IsLegalHoldActive reports whether a legal hold is currently in effect. The purge
// schedulers call this each tick and skip when it returns true; on error they must
// fail SAFE (skip the purge), so a transient lookup failure never risks destroying
// data that may be under hold.
func (c *KeyorixCore) IsLegalHoldActive(ctx context.Context) (bool, error) {
	hold, err := c.storage.GetActiveLegalHold(ctx)
	if err != nil {
		return false, err
	}
	return hold != nil, nil
}

// PlaceLegalHold activates a deployment-wide legal hold with a reason. Refuses if a
// hold is already active. actorID is the placing admin.
func (c *KeyorixCore) PlaceLegalHold(ctx context.Context, actorID uint, reason string) (*models.LegalHold, error) {
	if reason == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a reason is required to place a legal hold")
	}
	if active, err := c.storage.GetActiveLegalHold(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	} else if active != nil {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a legal hold is already active")
	}
	hold, err := c.storage.CreateLegalHold(ctx, &models.LegalHold{
		Reason: reason, PlacedBy: actorID, PlacedAt: c.now(), Released: false,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventLegalHoldPlaced, actorPtr(actorID), nil,
		fmt.Sprintf("legal hold %d placed: %s", hold.ID, reason))
	return hold, nil
}

// LiftLegalHold releases the active hold so the purge jobs resume. Refuses if no
// hold is active. actorID is the lifting admin.
func (c *KeyorixCore) LiftLegalHold(ctx context.Context, actorID uint) error {
	hold, err := c.storage.GetActiveLegalHold(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if hold == nil {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "no legal hold is active")
	}
	now := c.now()
	hold.Released = true
	hold.ReleasedBy = actorID
	hold.ReleasedAt = &now
	if err := c.storage.UpdateLegalHold(ctx, hold); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventLegalHoldLifted, actorPtr(actorID), nil,
		fmt.Sprintf("legal hold %d lifted", hold.ID))
	return nil
}
