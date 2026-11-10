package store

// #3944: the walk and its row count are separate statements, so a retention
// purge can remove rows the walk already visited before the count runs. The
// count then came out below the rows walked and a valid chain read broken. A
// delete can only lower the count; rows outside the walk (id 0, NULL, a
// duplicated id) are the only thing that raises it.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// afterFirstAuditBatch runs fn once, right after the walk's first id-ordered
// batch read of audit_events. db is the statement's own handle, so fn inside
// the migration's pre-flight runs in that transaction.
func afterFirstAuditBatch(t *testing.T, ls *LocalStorage, fn func(db *gorm.DB)) {
	t.Helper()
	var once sync.Once
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("test:after_first_audit_batch", func(db *gorm.DB) {
		if _, batch := db.Statement.Dest.(*[]*models.AuditEvent); batch {
			once.Do(func() { fn(db.Session(&gorm.Session{NewDB: true})) })
		}
	}))
}

// purgeThrough runs the real retention delete after the first batch read: it
// removes every row older than keep.
func purgeThrough(t *testing.T, ls *LocalStorage, keep *models.AuditEvent) {
	t.Helper()
	afterFirstAuditBatch(t, ls, func(*gorm.DB) {
		n, _, err := ls.DeleteAuditLogsBefore(context.Background(), keep.EventTime)
		require.NoError(t, err)
		require.Positive(t, n, "test bug: the purge removed nothing")
	})
}

func deleteRowAfterFirstBatch(t *testing.T, ls *LocalStorage, id uint) {
	t.Helper()
	afterFirstAuditBatch(t, ls, func(db *gorm.DB) {
		require.NoError(t, db.Exec(`DELETE FROM audit_events WHERE id = ?`, id).Error)
	})
}

func testPurgeBetweenWalkAndCount(t *testing.T, chain func(*testing.T, int) (*LocalStorage, []*models.AuditEvent)) {
	t.Run("full walk", func(t *testing.T) {
		ls, rows := chain(t, 6)
		purgeThrough(t, ls, rows[2])
		v, err := ls.VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		assert.Equal(t, rows[5].ID, v.HeadID)
		assert.Equal(t, int64(6), v.ChainedEvents)
	})
	t.Run("pinned segment losing its seed", func(t *testing.T) {
		ls, rows := chain(t, 6)
		purgeThrough(t, ls, rows[4])
		v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[3].ID, SeedHash: rows[3].EntryHash})
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		assert.Equal(t, rows[5].ID, v.HeadID)
	})
}

func TestVerifyAuditChain_PurgeBetweenWalkAndCountStaysValid(t *testing.T) {
	testPurgeBetweenWalkAndCount(t, segmentChain)
}

func TestVerifyAuditChain_PurgeBetweenWalkAndCountStaysValid_Postgres(t *testing.T) {
	testPurgeBetweenWalkAndCount(t, pgSegmentChain)
}

// Rows outside the walk still break it when a delete lands in the same window,
// as long as they outnumber the rows deleted.
func TestVerifyAuditChain_RowsOutsideTheWalkOutnumberingAPurgeStayBroken(t *testing.T) {
	t.Run("id 0 and a negative id", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		insertForgedAuditRow(t, ls.db, -7)
		deleteRowAfterFirstBatch(t, ls, rows[0].ID)
		assertWalkNotValid(t, ls)
	})
	t.Run("NULL ids", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		dropAuditEventsPK(t, ls.db)
		insertForgedAuditRow(t, ls.db, nil)
		insertForgedAuditRow(t, ls.db, nil)
		deleteRowAfterFirstBatch(t, ls, rows[0].ID)
		assertWalkNotValid(t, ls)
	})
	t.Run("duplicated id the walk ended on", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		dropAuditEventsPK(t, ls.db)
		for range 2 {
			require.NoError(t, ls.db.Exec(`INSERT INTO audit_events SELECT * FROM audit_events WHERE id = ? LIMIT 1`, rows[3].ID).Error)
		}
		deleteRowAfterFirstBatch(t, ls, rows[2].ID)
		v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, MaxRows: 2})
		require.NoError(t, err)
		assert.False(t, v.Valid, "the extra copies sit under the id the walk ended on")
		assert.Contains(t, v.Reason, "outside the chain")
	})
}

// A delete that exactly offsets a stray row can hide it from the walk it
// raced, but not from the next one: the stray row is still in the table.
func TestVerifyAuditChain_StrayRowOffsetByAPurgeIsCaughtByTheNextWalk(t *testing.T) {
	ls, rows := segmentChain(t, 6)
	insertForgedAuditRow(t, ls.db, 0)
	deleteRowAfterFirstBatch(t, ls, rows[5].ID)
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	assertWalkNotValid(t, ls)
}

// The migration's pre-flight excludes the retention purge (same advisory lock
// on Postgres, one transaction on SQLite), so unlike the online walk it has no
// race to tolerate: a delete inside its window is an unsanctioned one.
func testMigratePreflightDelete(t *testing.T, chain func(*testing.T, int) (*LocalStorage, []*models.AuditEvent)) {
	t.Run("a delete in the window is a refusal", func(t *testing.T) {
		ls, rows := chain(t, 6)
		deleteRowAfterFirstBatch(t, ls, rows[0].ID)
		_, err := ls.MigrateAuditChainEncoding(context.Background(), true, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "outside the chain", "the count refused, not a hash link")
	})
	t.Run("rows outside the walk still refuse", func(t *testing.T) {
		ls, rows := chain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		insertForgedAuditRow(t, ls.db, -7)
		deleteRowAfterFirstBatch(t, ls, rows[0].ID)
		_, err := ls.MigrateAuditChainEncoding(context.Background(), true, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "outside the chain")
	})
}

func TestMigrateAuditChainEncoding_PreflightCountRefusesDeletes(t *testing.T) {
	testMigratePreflightDelete(t, segmentChain)
}

func TestMigrateAuditChainEncoding_PreflightCountRefusesDeletes_Postgres(t *testing.T) {
	testMigratePreflightDelete(t, pgSegmentChain)
}
