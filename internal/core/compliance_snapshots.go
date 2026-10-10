// compliance_snapshots.go — TakeComplianceSnapshot and ListComplianceSnapshots.
//
// TakeComplianceSnapshot runs a full compliance posture evaluation and persists
// the CompliancePostureSnapshot for that calendar day. It fails closed (#2834):
// if any sub-rollup could not be read, or the row cannot be written, nothing is
// persisted and an error is returned -- never a success with partial counts.
//
// ListComplianceSnapshots returns recent snapshots for trend display without
// triggering a full posture evaluation.
package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrCompliancePostureDegraded is returned (wrapped) by TakeComplianceSnapshot when
// one or more posture sub-rollups failed to read. No snapshot is persisted.
var ErrCompliancePostureDegraded = errors.New("compliance posture is degraded; snapshot not persisted")

// TakeComplianceSnapshot evaluates the posture and persists the snapshot for
// today's UTC date. A degraded posture (any sub-count/list read failed) returns
// ErrCompliancePostureDegraded without writing; a failed write is returned too.
// The error names the failed areas only, not the underlying error text.
func (c *KeyorixCore) TakeComplianceSnapshot(ctx context.Context) (*models.CompliancePostureSnapshot, error) {
	posture, snap, err := c.computeCompliancePosture(ctx)
	if err != nil {
		return nil, fmt.Errorf("TakeComplianceSnapshot: %w", err)
	}
	if posture.Degraded {
		return nil, fmt.Errorf("TakeComplianceSnapshot: %w (unreadable: %s)",
			ErrCompliancePostureDegraded, strings.Join(degradedAreas(posture), ", "))
	}
	if err := c.storage.SaveCompliancePostureSnapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("TakeComplianceSnapshot: persist snapshot: %w", err)
	}
	return snap, nil
}

// degradedAreas returns the area name of each DegradedReasons entry (the text
// before the first ": "), de-duplicated in order.
func degradedAreas(p *CompliancePosture) []string {
	seen := make(map[string]bool, len(p.DegradedReasons))
	var areas []string
	for _, r := range p.DegradedReasons {
		area, _, _ := strings.Cut(r, ": ")
		if !seen[area] {
			seen[area] = true
			areas = append(areas, area)
		}
	}
	return areas
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
