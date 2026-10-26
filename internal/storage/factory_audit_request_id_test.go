package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/logging"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// requireAuditRequestIDAddedOnUpgrade models an epoch-5 database that already
// holds a chained audit history: it migrates, writes chained rows, drops
// audit_events.request_id (the epoch-5 schema), and migrates again. The column
// must come back, every pre-existing row must read NULL, the chain must still
// verify, and a new row written in a request context must carry the server id.
// It returns nothing; relfilenode, when non-nil, reports the table's storage file
// before and after the upgrade so the Postgres twin can assert no table rewrite.
func requireAuditRequestIDAddedOnUpgrade(t *testing.T, db *gorm.DB, relfilenode func() int64) {
	t.Helper()
	ctx := context.Background()
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.True(t, columnExists(db, "audit_events", "request_id"), "a fresh install has the column")

	ls := store.NewLocalStorage(db)
	base := time.Now().UTC()
	for i := range 3 {
		tr := true
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", Description: "pre-upgrade", Success: &tr,
			EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}))
	}
	require.NoError(t, db.Exec("ALTER TABLE audit_events DROP COLUMN request_id").Error)
	require.False(t, columnExists(db, "audit_events", "request_id"))

	var before int64
	if relfilenode != nil {
		before = relfilenode()
	}
	require.NoError(t, f.migrateDatabase(db), "the epoch-6 upgrade migration")
	require.True(t, columnExists(db, "audit_events", "request_id"), "the upgrade adds the column")
	if relfilenode != nil {
		require.Equal(t, before, relfilenode(), "adding the nullable column must not rewrite audit_events")
	}
	require.NoError(t, f.migrateDatabase(db), "re-running the migration must be a no-op")

	var nonNull int64
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM audit_events WHERE request_id IS NOT NULL").Scan(&nonNull).Error)
	require.Zero(t, nonNull, "rows written before the upgrade read as NULL")

	reqCtx, h := logging.WithHolder(ctx)
	h.SetServerRequestID("0123456789abcdef01234567")
	tr := true
	ls = store.NewLocalStorage(db)
	require.NoError(t, ls.LogAuditEvent(reqCtx, &models.AuditEvent{
		EventType: "secret.read", Description: "post-upgrade", Success: &tr,
		EventTime: base.Add(5 * time.Second), ActorType: "user",
	}))
	var got []struct{ RequestID *string }
	require.NoError(t, db.Raw("SELECT request_id FROM audit_events ORDER BY id").Scan(&got).Error)
	require.Len(t, got, 4)
	require.NotNil(t, got[3].RequestID)
	require.Equal(t, "0123456789abcdef01234567", *got[3].RequestID)

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, v.Valid, "the chain spanning the upgrade still verifies")
	require.Equal(t, int64(4), v.ChainedEvents)
}

func TestAuditRequestID_AddedOnUpgrade_SQLite(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "audit-request-id.db"))
	require.NoError(t, err)
	requireAuditRequestIDAddedOnUpgrade(t, db, nil)
}

// Postgres twin. Skips without KEYORIX_TEST_PG_DSN. Also asserts the ADD COLUMN
// is catalog-only: audit_events keeps its relfilenode (a rewrite assigns a new one).
func TestAuditRequestID_Postgres_AddedOnUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	requireAuditRequestIDAddedOnUpgrade(t, db, func() int64 {
		var n int64
		require.NoError(t, db.Raw("SELECT pg_relation_filenode('audit_events')").Scan(&n).Error)
		return n
	})
}
