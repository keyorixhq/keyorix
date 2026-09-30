// compliance_snapshots.go — TakeComplianceSnapshot and ListComplianceSnapshots.
//
// TakeComplianceSnapshot runs a full compliance posture evaluation and returns
// the persisted CompliancePostureSnapshot for that calendar day (same row that
// GetCompliancePosture already saves as a side-effect, now surfaced explicitly).
//
// ListComplianceSnapshots returns recent snapshots for trend display without
// triggering a full posture evaluation.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TakeComplianceSnapshot runs GetCompliancePosture and returns the
// CompliancePostureSnapshot that was persisted for today's UTC date.
// Errors from GetCompliancePosture are propagated; a failure to persist the
// snapshot (best-effort inside GetCompliancePosture) does not surface here —
// the posture is still returned via the in-memory buildCompliancePostureSnapshot
// result captured below.
func (c *KeyorixCore) TakeComplianceSnapshot(ctx context.Context) (*models.CompliancePostureSnapshot, error) {
	posture, err := c.GetCompliancePosture(ctx)
	if err != nil {
		return nil, fmt.Errorf("TakeComplianceSnapshot: %w", err)
	}
	today := truncateToUTCDay(c.now())
	return buildCompliancePostureSnapshot(posture, today), nil
}

// EventComplianceSnapshotTaken is audited on every explicit POST
// /compliance/snapshots trigger (F4, audit-completeness campaign).
// GetCompliancePosture persists a snapshot row as a side effect on every call
// (including the plain GET dashboard view), so this event is written only
// from the explicit on-demand trigger path, not from inside
// GetCompliancePosture itself — an audit event on every dashboard view would
// misrepresent routine reads as compliance-evidence-capture actions.
const EventComplianceSnapshotTaken = "compliance.snapshot_taken"

// LogComplianceSnapshotTaken records an explicit compliance-snapshot trigger.
// actorID is the requesting caller (0 = none, e.g. a scheduled trigger).
func (c *KeyorixCore) LogComplianceSnapshotTaken(ctx context.Context, actorID uint, snap *models.CompliancePostureSnapshot) {
	c.writeAuditEvent(ctx, EventComplianceSnapshotTaken, actorPtr(actorID), nil,
		fmt.Sprintf("compliance posture snapshot taken for %s", snap.SnapshotDate.Format("2006-01-02")))
}

// ListComplianceSnapshots returns up to limit saved CompliancePostureSnapshots
// ordered by snapshot_date descending. Passing limit ≤ 0 uses a default of 90.
func (c *KeyorixCore) ListComplianceSnapshots(ctx context.Context, limit int) ([]*models.CompliancePostureSnapshot, error) {
	snaps, err := c.storage.ListCompliancePostureSnapshots(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("ListComplianceSnapshots: %w", err)
	}
	return snaps, nil
}
