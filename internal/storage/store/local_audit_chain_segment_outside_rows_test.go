package store

// AUDIT-VERIFY-ONLINE-1 item 1 (#3808, the incremental path): a pinned segment
// (AfterID > 0: the request-time tail check from the latest checkpoint, and
// every rolling-cycle segment after the first) counted only the rows after its
// seed. An id 0 row, a NULL id or a second row under the seed's id sat outside
// every such segment, so GET /audit/verify and gRPC VerifyAuditChain in
// incremental mode read valid until the rolling cycle next walked from the
// chain start (up to a full cycle later). The segment now also counts the rows
// no keyset walk can reach (id < 1, NULL id) and its seed row.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func assertSegmentNotValid(t *testing.T, ls *LocalStorage, seed *models.AuditEvent) {
	t.Helper()
	v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: seed.ID, SeedHash: seed.EntryHash})
	require.NoError(t, err)
	assert.False(t, v.Valid, "a row outside every keyset walk must not leave a pinned segment valid")
	assert.Contains(t, v.Reason, "outside the chain")
}

func TestVerifyAuditChainSegment_RowsNoWalkReachesAreNotValid(t *testing.T) {
	t.Run("id 0 under a tail segment", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("id 0 under a tail segment with nothing after the seed", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		assertSegmentNotValid(t, ls, rows[5])
	})
	t.Run("negative id", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, -7)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("NULL id", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		dropAuditEventsPK(t, ls.db)
		insertForgedAuditRow(t, ls.db, nil)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("a second row under the seed's id", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		dropAuditEventsPK(t, ls.db)
		require.NoError(t, ls.db.Exec(`INSERT INTO audit_events SELECT * FROM audit_events WHERE id = ?`, rows[3].ID).Error)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("an intact chain stays valid from every seed", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		for _, seed := range rows {
			v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: seed.ID, SeedHash: seed.EntryHash})
			require.NoError(t, err)
			assert.True(t, v.Valid, "seed #%d: %s", seed.ID, v.Reason)
		}
		v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, ThroughID: rows[3].ID})
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
	})
}

// The encoding migration's pre-flight walk refuses a chain the online verifier
// reads broken: an id 0 row it would otherwise leave outside the re-hashed
// chain.
func TestMigrateAuditChainEncoding_RefusesRowsOutsideTheWalk(t *testing.T) {
	ls, _ := segmentChain(t, 4)
	insertForgedAuditRow(t, ls.db, 0)
	_, err := ls.MigrateAuditChainEncoding(context.Background(), true, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside the chain")
}

// pgSegmentChain is segmentChain over an isolated PostgreSQL schema.
func pgSegmentChain(t *testing.T, n int) (*LocalStorage, []*models.AuditEvent) {
	t.Helper()
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	var rows []*models.AuditEvent
	for i := range n {
		rows = append(rows, appendEvent(t, ls, "secret.read", "e", at.Add(time.Duration(i)*time.Second)))
	}
	return ls, rows
}

// dropAuditEventsPKPostgres leaves id a plain nullable column (the PostgreSQL
// counterpart of dropAuditEventsPK).
func dropAuditEventsPKPostgres(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec(`ALTER TABLE audit_events DROP CONSTRAINT audit_events_pkey`).Error)
	require.NoError(t, db.Exec(`ALTER TABLE audit_events ALTER COLUMN id DROP NOT NULL`).Error)
}

// PostgreSQL's bigserial accepts an explicit id 0 (pg-gated); the same cases
// as TestVerifyAuditChainSegment_RowsNoWalkReachesAreNotValid run on it.
func TestVerifyAuditChainSegment_IDZeroRowNotValid_Postgres(t *testing.T) {
	ls, rows := pgSegmentChain(t, 4)
	v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[2].ID, SeedHash: rows[2].EntryHash})
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	insertForgedAuditRow(t, ls.db, 0)
	assertSegmentNotValid(t, ls, rows[2])
	_, err = ls.MigrateAuditChainEncoding(context.Background(), true, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside the chain")
}

func TestVerifyAuditChainSegment_RowsNoWalkReachesAreNotValid_Postgres(t *testing.T) {
	t.Run("id 0 under a tail segment with nothing after the seed", func(t *testing.T) {
		ls, rows := pgSegmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		assertSegmentNotValid(t, ls, rows[5])
	})
	t.Run("negative id", func(t *testing.T) {
		ls, rows := pgSegmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, -7)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("NULL id", func(t *testing.T) {
		ls, rows := pgSegmentChain(t, 6)
		dropAuditEventsPKPostgres(t, ls.db)
		insertForgedAuditRow(t, ls.db, nil)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("a second row under the seed's id", func(t *testing.T) {
		ls, rows := pgSegmentChain(t, 6)
		dropAuditEventsPKPostgres(t, ls.db)
		require.NoError(t, ls.db.Exec(`INSERT INTO audit_events SELECT * FROM audit_events WHERE id = ?`, rows[3].ID).Error)
		assertSegmentNotValid(t, ls, rows[3])
	})
	t.Run("an intact chain stays valid from every seed", func(t *testing.T) {
		ls, rows := pgSegmentChain(t, 6)
		for _, seed := range rows {
			v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: seed.ID, SeedHash: seed.EntryHash})
			require.NoError(t, err)
			assert.True(t, v.Valid, "seed #%d: %s", seed.ID, v.Reason)
		}
		v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, ThroughID: rows[3].ID})
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
	})
}
