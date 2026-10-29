package storage

// AUDIT-REQUEST-ID-2 (schema epoch 9): an install migrated by an epoch-8 binary has
// pending_audit_events without request_id. migrateDatabase must add it (nullable, no
// default: catalog-only on PostgreSQL), or a request that owes an audit row cannot
// record its id and the upgraded install fails every owed-audit write.

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func requirePendingAuditRequestIDAddedOnUpgrade(t *testing.T, db *gorm.DB, relfilenode func() int64) {
	t.Helper()
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.True(t, columnExists(db, "pending_audit_events", "request_id"), "a fresh install has the column")

	// The epoch-8 shape: the table as it was, holding a record an epoch-8 binary wrote.
	require.NoError(t, db.Exec("ALTER TABLE pending_audit_events DROP COLUMN request_id").Error)
	require.False(t, columnExists(db, "pending_audit_events", "request_id"))
	require.NoError(t, db.Exec(`INSERT INTO pending_audit_events (event_type, event, attempts) VALUES ('secret.suspended', '{}', 0)`).Error)

	var before int64
	if relfilenode != nil {
		before = relfilenode()
	}
	require.NoError(t, f.migrateDatabase(db), "the epoch-9 upgrade migration")
	require.True(t, columnExists(db, "pending_audit_events", "request_id"), "the upgrade adds the column")
	if relfilenode != nil {
		require.Equal(t, before, relfilenode(), "adding the nullable column must not rewrite pending_audit_events")
	}
	require.NoError(t, f.migrateDatabase(db), "re-running the migration must be a no-op")

	// The record an epoch-8 binary left behind reads as "no request id".
	var old models.PendingAuditEvent
	require.NoError(t, db.First(&old).Error)
	require.Nil(t, old.RequestID)

	// A record written after the upgrade carries one.
	id := "0123456789abcdef01234567"
	require.NoError(t, db.Create(&models.PendingAuditEvent{EventType: "secret.suspended", Event: "{}", RequestID: &id}).Error)
	var got []models.PendingAuditEvent
	require.NoError(t, db.Order("id").Find(&got).Error)
	require.Len(t, got, 2)
	require.Nil(t, got[0].RequestID)
	require.NotNil(t, got[1].RequestID)
	require.Equal(t, id, *got[1].RequestID)
}

func TestPendingAuditRequestID_AddedOnUpgrade_SQLite(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pending-request-id.db"))
	require.NoError(t, err)
	requirePendingAuditRequestIDAddedOnUpgrade(t, db, nil)
}

// Postgres twin. Skips without KEYORIX_TEST_PG_DSN. Also asserts the ADD COLUMN is
// catalog-only: pending_audit_events keeps its relfilenode (a rewrite assigns a new one).
func TestPendingAuditRequestID_Postgres_AddedOnUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	requirePendingAuditRequestIDAddedOnUpgrade(t, db, func() int64 {
		var n int64
		require.NoError(t, db.Raw("SELECT pg_relation_filenode('pending_audit_events')").Scan(&n).Error)
		return n
	})
}
