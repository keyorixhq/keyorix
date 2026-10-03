// audit_retention_prefix_test.go — INV-STORE-22 guards (#2633): the audit
// retention purge deletes only a contiguous id prefix of audit_events, under
// the same KEYAUDIT serialization LogAuditEvent appends under.
package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// appendChainedAt appends one chained audit event (via the real LogAuditEvent
// path, so prev_hash/entry_hash are genuine) with the given event_time.
func appendChainedAt(t *testing.T, ls *LocalStorage, desc string, at time.Time) {
	t.Helper()
	require.NoError(t, ls.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: "secret.read", Description: desc, EventTime: at,
	}))
}

// seedInvertedPairTrail builds the #2633 shape: id order and event_time order
// disagree across the cutoff. Row 2 has a LOWER id but a NEWER event_time than
// row 3 (concurrent writers / HA clock skew), and the cutoff falls between
// them:
//
//	id 1  old  (-40d)
//	id 2  new  (-1d)    <- inverted pair: lower id, newer event_time
//	id 3  old  (-35d)
//	id 4  new  (-1d)
//
// Returns the cutoff (-30d).
func seedInvertedPairTrail(t *testing.T, ls *LocalStorage) time.Time {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	appendChainedAt(t, ls, "row1-old", now.AddDate(0, 0, -40))
	appendChainedAt(t, ls, "row2-new", now.AddDate(0, 0, -1))
	appendChainedAt(t, ls, "row3-old", now.AddDate(0, 0, -35))
	appendChainedAt(t, ls, "row4-new", now.AddDate(0, 0, -1))
	return now.AddDate(0, 0, -30)
}

func survivingAuditDescriptions(t *testing.T, ls *LocalStorage) []string {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, ls.db.Order("id ASC").Find(&rows).Error)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Description)
	}
	return out
}

// assertInvertedPairPurgeKeepsChainVerifiable is the shared body of the
// INV-STORE-22 guards: purge across the inverted pair, then verify the chain
// from the returned anchor exactly as core.VerifyAuditChain would (after
// authenticating it). Before the fix, row 3 (old, but above the newer row 2)
// was deleted out of the middle of the chain: row 4's prev_hash then pointed
// at a deleted row and verification reported tampering.
func assertInvertedPairPurgeKeepsChainVerifiable(t *testing.T, ls *LocalStorage, purge func(cutoff time.Time) (int64, *storage.AuditChainAnchor, error)) {
	t.Helper()
	ctx := context.Background()
	cutoff := seedInvertedPairTrail(t, ls)

	deleted, anchor, err := purge(cutoff)
	require.NoError(t, err)

	v, err := ls.VerifyAuditChain(ctx, anchor)
	require.NoError(t, err)
	require.True(t, v.Valid, "audit chain must verify after a retention purge (first broken id %d: %s)", derefUint(v.FirstBrokenID), v.Reason)

	assert.Equal(t, int64(1), deleted, "only the contiguous old prefix (row 1) may be deleted")
	assert.Equal(t, []string{"row2-new", "row3-old", "row4-new"}, survivingAuditDescriptions(t, ls),
		"the newer row of the inverted pair and everything after it must survive, including the old row 3 above it")
	require.NotNil(t, anchor, "the purge reached into the chained region, so it must re-anchor")
	assert.Equal(t, uint(2), anchor.RowID, "anchor is the first surviving id")
}

// TestDeleteAuditLogsBefore_InvertedPair_DeletesOnlyContiguousIDPrefix guards
// INV-STORE-22 (#2633) on the base (non-transactional) store.
func TestDeleteAuditLogsBefore_InvertedPair_DeletesOnlyContiguousIDPrefix(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	assertInvertedPairPurgeKeepsChainVerifiable(t, ls, func(cutoff time.Time) (int64, *storage.AuditChainAnchor, error) {
		return ls.DeleteAuditLogsBefore(context.Background(), cutoff)
	})
}

// TestDeleteAuditLogsBefore_InvertedPair_InsideTransaction is the same guard in
// the production call shape: core.PurgeAuditLogs calls DeleteAuditLogsBefore on
// a transaction-scoped store (WithTransaction).
func TestDeleteAuditLogsBefore_InvertedPair_InsideTransaction(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	assertInvertedPairPurgeKeepsChainVerifiable(t, ls, func(cutoff time.Time) (n int64, a *storage.AuditChainAnchor, err error) {
		txErr := ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
			n, a, err = tx.DeleteAuditLogsBefore(context.Background(), cutoff)
			return err
		})
		if err == nil {
			err = txErr
		}
		return n, a, err
	})
}

// TestDeleteAuditLogsBefore_OldestRowNewer_DeletesNothing: when the lowest id is
// itself newer than the cutoff, the contiguous old prefix is empty — nothing is
// deleted even though older rows exist further up the chain.
func TestDeleteAuditLogsBefore_OldestRowNewer_DeletesNothing(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	appendChainedAt(t, ls, "row1-new", now.AddDate(0, 0, -1))
	appendChainedAt(t, ls, "row2-old", now.AddDate(0, 0, -40))

	deleted, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
	assert.Nil(t, anchor)
	assert.Equal(t, []string{"row1-new", "row2-old"}, survivingAuditDescriptions(t, ls))
	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
}

// TestDeleteAuditLogsBefore_AllOld_DeletesEverything: with no row at or after
// the cutoff, the whole table is the old prefix — same result as before the fix.
func TestDeleteAuditLogsBefore_AllOld_DeletesEverything(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	appendChainedAt(t, ls, "row1-old", now.AddDate(0, 0, -40))
	appendChainedAt(t, ls, "row2-old", now.AddDate(0, 0, -50))

	deleted, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)
	assert.Nil(t, anchor, "table is empty after the purge — nothing to re-anchor")
	assert.Empty(t, survivingAuditDescriptions(t, ls))
}

// TestDeleteAuditLogsBefore_WaitsForAuditChainMutex guards the in-process half
// of INV-STORE-22's lock: a purge on the base store must not run while an
// audit append holds auditChainMu (the append's read-head+insert section).
func TestDeleteAuditLogsBefore_WaitsForAuditChainMutex(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	cutoff := seedInvertedPairTrail(t, ls)

	ls.auditChainMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, _, err := ls.DeleteAuditLogsBefore(context.Background(), cutoff)
		done <- err
	}()
	select {
	case err := <-done:
		ls.auditChainMu.Unlock()
		t.Fatalf("DeleteAuditLogsBefore ran while auditChainMu was held (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	ls.auditChainMu.Unlock()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("DeleteAuditLogsBefore did not complete after auditChainMu was released")
	}
}

func derefUint(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

// TestDeleteAuditLogsBefore_NullEventTime_StopsThePrefix: a row whose event_time
// is NULL is not "older than cutoff" (the pre-#2633 "event_time < cutoff" never
// deleted it either), so it ends the deletable prefix just like a newer row —
// the old row above it must survive rather than be cut out from around it.
func TestDeleteAuditLogsBefore_NullEventTime_StopsThePrefix(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, desc := range []string{"row1-old", "row2-null", "row3-old", "row4-new"} {
		require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", Description: desc, EventTime: now}).Error)
	}
	require.NoError(t, ls.db.Exec("UPDATE audit_events SET event_time = ? WHERE description IN ('row1-old', 'row3-old')", now.AddDate(0, 0, -40)).Error)
	require.NoError(t, ls.db.Exec("UPDATE audit_events SET event_time = NULL WHERE description = 'row2-null'").Error)

	deleted, _, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
	assert.Equal(t, []string{"row2-null", "row3-old", "row4-new"}, survivingAuditDescriptions(t, ls))
}

// TestDeleteAuditLogsBefore_ConcurrentAppendsAndTxPurges_ProductionSQLiteDSN
// races LogAuditEvent appenders (old and new event_times interleaved, so id
// order and event_time order disagree constantly) against purges in the
// production call shape — inside WithTransaction, on a file database opened with
// the production SQLite pragmas (WAL, _txlock=immediate, so every transaction
// holds the write lock from BEGIN). Every append and purge must succeed — in
// particular, the purge must not wait on auditChainMu while its transaction
// holds the write lock an appender holding auditChainMu is waiting for — and
// the chain must verify from the last re-anchor afterwards.
func TestDeleteAuditLogsBefore_ConcurrentAppendsAndTxPurges_ProductionSQLiteDSN(t *testing.T) {
	ls := newProductionDSNAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.AddDate(0, 0, -30)

	const appenders, perAppender, purges = 4, 25, 15
	var wg sync.WaitGroup
	errs := make(chan error, appenders*perAppender+purges)
	for a := 0; a < appenders; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			for i := 0; i < perAppender; i++ {
				at := now.Add(-time.Minute)
				if (a+i)%2 == 0 {
					at = now.AddDate(0, 0, -40)
				}
				if err := ls.LogAuditEvent(ctx, &models.AuditEvent{
					EventType: "secret.read", Description: fmt.Sprintf("a%d-%d", a, i), EventTime: at,
				}); err != nil {
					errs <- fmt.Errorf("append: %w", err)
				}
			}
		}(a)
	}
	var anchorMu sync.Mutex
	var lastAnchor *storage.AuditChainAnchor
	wg.Add(1)
	go func() {
		defer wg.Done()
		for p := 0; p < purges; p++ {
			if err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
				_, a, err := tx.DeleteAuditLogsBefore(ctx, cutoff)
				if err == nil && a != nil {
					anchorMu.Lock()
					lastAnchor = a
					anchorMu.Unlock()
				}
				return err
			}); err != nil {
				errs <- fmt.Errorf("purge: %w", err)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	v, err := ls.VerifyAuditChain(ctx, lastAnchor)
	require.NoError(t, err)
	require.True(t, v.Valid, "audit chain must verify after concurrent appends and purges (first broken id %d: %s)", derefUint(v.FirstBrokenID), v.Reason)
}

// newProductionDSNAuditStore opens a file SQLite database with the production
// pragmas (internal/storage/factory.go sqliteDSN: WAL, _txlock=immediate, so a
// transaction holds the write lock from BEGIN).
func newProductionDSNAuditStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "audit.db") +
		"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate&_synchronous=FULL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewLocalStorage(db)
}

// TestDeleteAuditLogsBefore_InTx_DoesNotWaitOnAuditChainMu pins the lock-order
// choice in DeleteAuditLogsBefore's doc comment, deterministically: the purge's
// transaction (production shape: WithTransaction, _txlock=immediate) already
// holds the SQLite write lock when an appender takes auditChainMu and blocks on
// its own BEGIN IMMEDIATE. If the in-transaction purge then waited on
// auditChainMu, each would wait on the other until the appender's write timeout
// gave up and dropped its audit event. The purge must complete without the
// mutex, and the appender must then succeed.
func TestDeleteAuditLogsBefore_InTx_DoesNotWaitOnAuditChainMu(t *testing.T) {
	ls := newProductionDSNAuditStore(t)
	ctx := context.Background()
	cutoff := seedInvertedPairTrail(t, ls)

	appendErr := make(chan error, 1)
	purgeErr := make(chan error, 1)
	go func() {
		purgeErr <- ls.WithTransaction(ctx, func(tx storage.Storage) error {
			go func() {
				appendErr <- ls.LogAuditEvent(ctx, &models.AuditEvent{
					EventType: "secret.read", Description: "blocked-appender", EventTime: time.Now().UTC(),
				})
			}()
			// Let the appender take auditChainMu and block on BEGIN IMMEDIATE
			// behind this transaction's write lock.
			time.Sleep(200 * time.Millisecond)
			_, _, err := tx.DeleteAuditLogsBefore(ctx, cutoff)
			return err
		})
	}()

	select {
	case err := <-purgeErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("in-transaction purge blocked behind an appender holding auditChainMu (lock-order inversion)")
	}
	require.NoError(t, <-appendErr, "the appender must succeed once the purge commits")
}
