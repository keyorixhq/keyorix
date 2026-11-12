package store

// #3944, the part #4079 left open: a retention purge that removes rows past
// the walk's cursor (a chain longer than one batch) leaves the next batch
// starting at a row whose prev_hash names a deleted predecessor. The walk
// cannot tell that from a row deleted outside a purge and stays broken, but it
// marks the verdict LinkBroken so the core layer (which can authenticate a
// re-read anchor) can walk again from a moved anchor. Every other failure is
// left unmarked.

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// overtakeChainLen is one full batch plus a few rows, so the walk reads a
// second batch after the purge.
const overtakeChainLen = auditChainVerifyBatch + 5

// afterFullAuditBatch runs fn once, right after the walk's first full batch
// read. Unlike afterFirstAuditBatch it tolerates fn reading audit_events.
func afterFullAuditBatch(t *testing.T, ls *LocalStorage, fn func(db *gorm.DB)) {
	t.Helper()
	var fired atomic.Bool
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("test:after_full_audit_batch", func(db *gorm.DB) {
		if batch, ok := db.Statement.Dest.(*[]*models.AuditEvent); ok && len(*batch) == auditChainVerifyBatch && fired.CompareAndSwap(false, true) {
			fn(db.Session(&gorm.Session{NewDB: true}))
		}
	}))
}

// purgePastCursor runs the real retention delete after the first full batch,
// removing every row older than keep (past the cursor), and returns where
// the anchor it produced will be stored.
func purgePastCursor(t *testing.T, ls *LocalStorage, keep *models.AuditEvent) *atomic.Pointer[storage.AuditChainAnchor] {
	t.Helper()
	var anchor atomic.Pointer[storage.AuditChainAnchor]
	afterFullAuditBatch(t, ls, func(*gorm.DB) {
		n, a, err := ls.DeleteAuditLogsBefore(context.Background(), keep.EventTime)
		require.NoError(t, err)
		require.Positive(t, n, "test bug: the purge removed nothing")
		require.NotNil(t, a, "test bug: the purge left no anchor")
		anchor.Store(a)
	})
	return &anchor
}

func testPurgeOvertakesWalk(t *testing.T, chain func(*testing.T, int) (*LocalStorage, []*models.AuditEvent)) {
	ctx := context.Background()
	t.Run("a purge past the cursor is marked, and the moved anchor verifies", func(t *testing.T) {
		ls, rows := chain(t, overtakeChainLen)
		keep := rows[auditChainVerifyBatch+2]
		anchor := purgePastCursor(t, ls, keep)
		v, err := ls.VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.False(t, v.Valid)
		assert.Equal(t, auditLinkMismatchReason, v.Reason)
		assert.True(t, v.LinkBroken)
		require.NotNil(t, anchor.Load())
		again, err := ls.VerifyAuditChain(ctx, anchor.Load())
		require.NoError(t, err)
		require.True(t, again.Valid, again.Reason)
		assert.False(t, again.LinkBroken)
		assert.Equal(t, rows[len(rows)-1].ID, again.HeadID)
		assert.Equal(t, int64(3), again.ChainedEvents)
	})
	t.Run("a purge before the first batch is marked", func(t *testing.T) {
		ls, rows := chain(t, 6)
		_, first, err := ls.DeleteAuditLogsBefore(ctx, rows[2].EventTime)
		require.NoError(t, err)
		require.NotNil(t, first)
		_, second, err := ls.DeleteAuditLogsBefore(ctx, rows[4].EventTime)
		require.NoError(t, err)
		v, err := ls.VerifyAuditChain(ctx, first)
		require.NoError(t, err)
		require.False(t, v.Valid)
		assert.Contains(t, v.Reason, "does not match the last retention re-anchor")
		assert.True(t, v.LinkBroken)
		again, err := ls.VerifyAuditChain(ctx, second)
		require.NoError(t, err)
		assert.True(t, again.Valid, again.Reason)
	})
	t.Run("a modified row is not marked", func(t *testing.T) {
		ls, rows := chain(t, 6)
		require.NoError(t, ls.db.Exec(`UPDATE audit_events SET description = 'rewritten' WHERE id = ?`, rows[3].ID).Error)
		v, err := ls.VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.False(t, v.Valid)
		assert.Contains(t, v.Reason, "event modified")
		assert.False(t, v.LinkBroken)
	})
	t.Run("rows outside the walk are not marked", func(t *testing.T) {
		ls, _ := chain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		v, err := ls.VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.False(t, v.Valid)
		assert.Contains(t, v.Reason, "outside the chain")
		assert.False(t, v.LinkBroken)
	})
	t.Run("a pinned segment is not marked", func(t *testing.T) {
		ls, rows := chain(t, 6)
		require.NoError(t, ls.db.Exec(`DELETE FROM audit_events WHERE id = ?`, rows[3].ID).Error)
		v, err := ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash})
		require.NoError(t, err)
		require.False(t, v.Valid)
		assert.Equal(t, auditLinkMismatchReason, v.Reason)
		assert.False(t, v.LinkBroken, "a pinned walk is not re-seeded from an anchor")
	})
}

func TestVerifyAuditChain_PurgeOvertakingTheWalkIsMarkedLinkBroken(t *testing.T) {
	testPurgeOvertakesWalk(t, segmentChain)
}

func TestVerifyAuditChain_PurgeOvertakingTheWalkIsMarkedLinkBroken_Postgres(t *testing.T) {
	testPurgeOvertakesWalk(t, pgSegmentChain)
}
