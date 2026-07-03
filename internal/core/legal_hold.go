// legal_hold.go — deployment-wide legal hold (ISO 27001 A.5.34 / eDiscovery / DORA
// record-keeping). While a hold is active the background purge/retention jobs are
// blocked from hard-deleting records (the schedulers call IsLegalHoldActive each
// tick), so data subject to litigation or investigation is preserved. Placing and
// lifting a hold are audited; the row history is the evidence of when holds applied.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
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

// legalHoldGuard returns a non-nil error when a deployment-wide legal hold is active OR
// its status cannot be confirmed — fail SAFE. The hard-delete purges call this at their
// top (inside the scheduler lock, immediately before the deletes) so a hold placed after
// the scheduler's pre-lock check still aborts the in-flight purge, never destroying
// records that may be under hold.
func (c *KeyorixCore) legalHoldGuard(ctx context.Context) error {
	held, err := c.IsLegalHoldActive(ctx)
	if err != nil {
		return fmt.Errorf("refusing to purge: could not confirm legal-hold status: %w", err)
	}
	if held {
		return fmt.Errorf("refusing to purge: a deployment-wide legal hold is active")
	}
	return nil
}

// PlaceLegalHold activates a deployment-wide legal hold with a reason. Refuses if a
// hold is already active. actorID is the placing admin.
//
// The active check below and the insert in CreateLegalHold are not atomic: two
// concurrent calls can both observe "no active hold" before either commits (#305).
// That TOCTOU window fails SAFE, not open — a partial unique index on legal_holds
// (released) WHERE released = false means only one of the two inserts can succeed,
// and the loser's CreateLegalHold returns storage.ErrLegalHoldAlreadyActive, which
// is mapped to the same "already active" client error as the pre-check below rather
// than a 500.
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
	if errors.Is(err, storage.ErrLegalHoldAlreadyActive) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a legal hold is already active")
	}
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
