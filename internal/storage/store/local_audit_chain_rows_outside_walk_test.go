package store

// #3808: the keyset walk (id > lastID, from 0) never visits an audit_events
// row with id 0, a NULL id, or a second row under an id a batch ended on (a
// schema without the primary key). Every row up to the last one walked must
// have been walked, or the online verification is not valid, as the offline
// verifier already reports (INV-AUDITVERIFY-every-row-walked).

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func insertForgedAuditRow(t *testing.T, db *gorm.DB, id any) {
	t.Helper()
	require.NoError(t, db.Exec(`INSERT INTO audit_events (id, event_type, description, event_time, actor_type, prev_hash, entry_hash, ip_address, diff, impersonation)
		VALUES (?, 'secret.read', 'forged', ?, 'user', 'x', 'y', '', '', false)`, id, time.Now().UTC()).Error)
}

// dropAuditEventsPK rebuilds audit_events (SQLite) with id as a plain column.
func dropAuditEventsPK(t *testing.T, db *gorm.DB) {
	t.Helper()
	var ddl string
	require.NoError(t, db.Raw(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'`).Scan(&ddl).Error)
	plain := regexp.MustCompile(`(?i)PRIMARY KEY( AUTOINCREMENT)?`).ReplaceAllString(ddl, "")
	require.NotEqual(t, ddl, plain, "test bug: no primary key in %s", ddl)
	for _, q := range []string{
		strings.Replace(plain, "audit_events", "audit_events_plain", 1),
		`INSERT INTO audit_events_plain SELECT * FROM audit_events`,
		`DROP TABLE audit_events`,
		`ALTER TABLE audit_events_plain RENAME TO audit_events`,
	} {
		require.NoError(t, db.Exec(q).Error)
	}
}

func assertWalkNotValid(t *testing.T, ls *LocalStorage) {
	t.Helper()
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a row outside the walk must not verify valid")
	assert.Contains(t, v.Reason, "outside the chain")
}

func TestVerifyAuditChain_RowsOutsideTheWalkAreNotValid(t *testing.T) {
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	t.Run("id 0", func(t *testing.T) {
		ls, _ := segmentChain(t, 6)
		insertForgedAuditRow(t, ls.db, 0)
		assertWalkNotValid(t, ls)
	})
	t.Run("id 0 on an empty chain", func(t *testing.T) {
		ls := newAuditChainTestStore(t)
		insertForgedAuditRow(t, ls.db, 0)
		assertWalkNotValid(t, ls)
	})
	t.Run("NULL id", func(t *testing.T) {
		ls, _ := segmentChain(t, 6)
		dropAuditEventsPK(t, ls.db)
		insertForgedAuditRow(t, ls.db, nil)
		assertWalkNotValid(t, ls)
	})
	t.Run("duplicate id on a batch boundary", func(t *testing.T) {
		ls := newAuditChainTestStore(t)
		for i := range auditChainVerifyBatch {
			appendEvent(t, ls, "secret.read", "e", at.Add(time.Duration(i)*time.Second))
		}
		v, err := ls.VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
		dropAuditEventsPK(t, ls.db)
		// An exact copy, so the walk is consistent whichever copy it visits.
		require.NoError(t, ls.db.Exec(`INSERT INTO audit_events SELECT * FROM audit_events WHERE id = ?`, auditChainVerifyBatch).Error)
		assertWalkNotValid(t, ls)
	})
	t.Run("a pinned segment is checked over its own range", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		dropAuditEventsPK(t, ls.db)
		require.NoError(t, ls.db.Exec(`INSERT INTO audit_events SELECT * FROM audit_events WHERE id = ?`, rows[3].ID).Error)
		// The row cap ends the walk on one copy of rows[3]'s id.
		v, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, MaxRows: 2})
		require.NoError(t, err)
		assert.False(t, v.Valid, "the other copy sits under the id the walk ended on")
		// A row below the seed is not this segment's to count.
		v, err = ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[4].ID, SeedHash: rows[4].EntryHash})
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
	})
	t.Run("an intact chain stays valid", func(t *testing.T) {
		ls, rows := segmentChain(t, 6)
		v, err := ls.VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		assert.Equal(t, int64(6), v.ChainedEvents)
		v, err = ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, MaxRows: 2})
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		assert.True(t, v.Truncated)
	})
}

// PostgreSQL's bigserial accepts an explicit id 0 as well (pg-gated).
func TestVerifyAuditChain_IDZeroRowNotValid_Postgres(t *testing.T) {
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for i := range 4 {
		appendEvent(t, ls, "secret.read", "e", at.Add(time.Duration(i)*time.Second))
	}
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	insertForgedAuditRow(t, db, 0)
	assertWalkNotValid(t, ls)
}
