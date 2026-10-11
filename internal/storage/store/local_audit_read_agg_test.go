// local_audit_read_agg_test.go — unit tests for GetSecretReadCounts (LocalStorage).
package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newReadAggStore opens a uniquely-named in-memory SQLite DB with the tables
// needed by GetSecretReadCounts (audit_events + users for the JOIN).
func newReadAggStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "localauditreadagg_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
	))
	return NewLocalStorage(db), db
}

func seedReadEvent(t *testing.T, db *gorm.DB, secretID, userID uint, at time.Time) {
	t.Helper()
	tru := true
	uid := userID
	sid := secretID
	evt := &models.AuditEvent{
		EventType:    "secret.read",
		UserID:       &uid,
		SecretNodeID: &sid,
		EventTime:    at,
		Success:      &tru,
	}
	require.NoError(t, db.Create(evt).Error)
}

// ── happy path ────────────────────────────────────────────────────────────────

func TestGetSecretReadCounts_HappyPath(t *testing.T) {
	ls, db := newReadAggStore(t)
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	until := now.Add(time.Hour)

	// User 1: 3 reads, user 2: 1 read.
	seedReadEvent(t, db, 10, 1, now.Add(-1*time.Hour))
	seedReadEvent(t, db, 10, 1, now.Add(-2*time.Hour))
	seedReadEvent(t, db, 10, 1, now.Add(-3*time.Hour))
	seedReadEvent(t, db, 10, 2, now.Add(-4*time.Hour))

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 10)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// User 1 should be first (highest count).
	assert.Equal(t, int64(3), entries[0].ReadCount)
	assert.Equal(t, int64(1), entries[1].ReadCount)
}

// ── events outside the window are excluded ────────────────────────────────────

func TestGetSecretReadCounts_OutsideWindowExcluded(t *testing.T) {
	ls, db := newReadAggStore(t)
	now := time.Now().UTC()
	since := now.Add(-1 * time.Hour)
	until := now

	// Two events — one inside, one before the window.
	seedReadEvent(t, db, 10, 1, now.Add(-30*time.Minute)) // inside
	seedReadEvent(t, db, 10, 1, now.Add(-2*time.Hour))    // before since → excluded

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, int64(1), entries[0].ReadCount)
}

// ── non-read events are excluded ─────────────────────────────────────────────

func TestGetSecretReadCounts_NonReadEventsExcluded(t *testing.T) {
	ls, db := newReadAggStore(t)
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	until := now.Add(time.Hour)

	uid := uint(1)
	sid := uint(10)
	tru := true
	// Insert a "secret.created" event — should be ignored.
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.created", UserID: &uid, SecretNodeID: &sid,
		EventTime: now.Add(-1 * time.Hour), Success: &tru,
	}).Error)
	// Insert a proper "secret.read" event.
	seedReadEvent(t, db, 10, 1, now.Add(-2*time.Hour))

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, int64(1), entries[0].ReadCount)
}

// ── different secret IDs don't bleed through ─────────────────────────────────

func TestGetSecretReadCounts_DifferentSecretExcluded(t *testing.T) {
	ls, db := newReadAggStore(t)
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	until := now.Add(time.Hour)

	// Reads on secret 10 and secret 99.
	seedReadEvent(t, db, 10, 1, now.Add(-1*time.Hour))
	seedReadEvent(t, db, 99, 1, now.Add(-1*time.Hour)) // different secret

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, int64(1), entries[0].ReadCount)
}

// ── no events → empty result ──────────────────────────────────────────────────

func TestGetSecretReadCounts_NoEvents(t *testing.T) {
	ls, _ := newReadAggStore(t)
	now := time.Now().UTC()

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, now.Add(-24*time.Hour), now, 10)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// ── limit is respected ────────────────────────────────────────────────────────

func TestGetSecretReadCounts_LimitRespected(t *testing.T) {
	ls, db := newReadAggStore(t)
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	until := now.Add(time.Hour)

	// 5 different users, each reading secret 10 once.
	for i := uint(1); i <= 5; i++ {
		seedReadEvent(t, db, 10, i, now.Add(-time.Duration(i)*time.Hour))
	}

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 3)
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

// ── username resolved from users table ───────────────────────────────────────

func TestGetSecretReadCounts_UsernameResolved(t *testing.T) {
	ls, db := newReadAggStore(t)
	now := time.Now().UTC()

	// Insert a real user.
	user := &models.User{Username: "alice"}
	require.NoError(t, db.Create(user).Error)

	since := now.Add(-24 * time.Hour)
	until := now.Add(time.Hour)
	seedReadEvent(t, db, 10, user.ID, now.Add(-1*time.Hour))

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "alice", entries[0].ActorUsername)
}

// newReadAggPGStore is newReadAggStore's PostgreSQL counterpart, isolated in
// its own dedicated schema (same pattern as local_transaction_pg_savepoint_test.go's
// newPGTxStore) so concurrent test runs sharing one Postgres instance don't
// collide. Skips (not fails) when KEYORIX_TEST_PG_DSN is unset, per this
// repo's "pg-gated" verification convention (docs/security-closures.tsv).
func newReadAggPGStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	schema := "readagg_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.AuditEvent{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return NewLocalStorage(db), db
}

// TestGetSecretReadCounts_PostgresUsernameResolved is SESSION-I's regression:
// GetSecretReadCounts' query SELECTs the LEFT-JOINed users.username column
// but only grouped by ae.user_id -- Postgres enforces the SQL standard's
// GROUP BY functional-dependency rule strictly and rejects that outright
// ("column \"u.username\" must appear in the GROUP BY clause or be used in
// an aggregate function"); SQLite has no such check at all, so every
// existing test in this file (all SQLite-only) passed regardless of whether
// the query was actually valid on Postgres. Confirmed live via SESSION-I's
// fresh-install API smoke driver running GET /api/v1/secrets/{id}/read-summary
// against a real Postgres backend -- it 500ed there and nowhere else.
func TestGetSecretReadCounts_PostgresUsernameResolved(t *testing.T) {
	ls, db := newReadAggPGStore(t)
	now := time.Now().UTC()

	user := &models.User{Username: "alice"}
	require.NoError(t, db.Create(user).Error)

	since := now.Add(-24 * time.Hour)
	until := now.Add(time.Hour)
	seedReadEvent(t, db, 10, user.ID, now.Add(-1*time.Hour))

	entries, err := ls.GetSecretReadCounts(context.Background(), 10, since, until, 10)
	require.NoError(t, err, "GetSecretReadCounts must not error on Postgres")
	require.Len(t, entries, 1)
	assert.Equal(t, "alice", entries[0].ActorUsername)
	assert.Equal(t, int64(1), entries[0].ReadCount)
}
