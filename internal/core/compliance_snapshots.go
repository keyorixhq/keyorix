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

const snapshotListDefaultLimit = 90

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

// ListComplianceSnapshots returns up to limit saved CompliancePostureSnapshots
// ordered by snapshot_date descending. Passing limit ≤ 0 uses a default of 90.
func (c *KeyorixCore) ListComplianceSnapshots(ctx context.Context, limit int) ([]*models.CompliancePostureSnapshot, error) {
	snaps, err := c.storage.ListCompliancePostureSnapshots(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("ListComplianceSnapshots: %w", err)
	}
	return snaps, nil
}
