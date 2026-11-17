package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// walkAuditChainRacingPurge is walkAuditChain for a walk from the chain start
// (seg.AfterID == 0, seeded from seg.Anchor) that a retention purge may run
// alongside (#3944). The walk holds no audit lock, so a purge that removes rows
// past its cursor, or runs between the caller's anchor read and the first
// batch, breaks a valid chain's links exactly like a row deleted outside a
// purge would (the storage walk marks those two failures LinkBroken).
//
// On such a failure the authenticated anchor is read again. Only when a
// sanctioned purge moved it forward is the chain walked once more, from the new
// anchor, re-verifying every surviving row; the result then carries it in
// Reanchored, whose PurgedEvents goes with the new count. An anchor that did
// not move (an unsanctioned delete, or a forged or stale anchor, which
// loadAuditRetentionAnchor ignores), a failure on the second walk, and every
// other failure keep the broken verdict.
func (c *KeyorixCore) walkAuditChainRacingPurge(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	v, err := c.walkAuditChain(ctx, seg)
	if err != nil || v.Valid || !v.LinkBroken {
		return v, err
	}
	moved, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to reload audit chain re-anchor: %w", err)
	}
	if moved == nil || (seg.Anchor != nil && moved.RowID <= seg.Anchor.RowID) {
		return v, nil
	}
	seg.Anchor = moved
	again, err := c.walkAuditChain(ctx, seg)
	if err != nil {
		return nil, err
	}
	again.Reanchored = moved
	if !again.Valid {
		again.Reason = fmt.Sprintf("after walking again from the retention re-anchor at audit event #%d (a purge ran during the first walk): %s", moved.RowID, again.Reason)
	}
	return again, nil
}
