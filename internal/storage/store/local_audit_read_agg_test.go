// local_audit_read_agg_test.go — unit tests for GetSecretReadCounts (LocalStorage).
package store

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var readAggTestCounter atomic.Int64

// newReadAggStore opens a uniquely-named in-memory SQLite DB with the tables
// needed by GetSecretReadCounts (audit_events + users for the JOIN).
func newReadAggStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	n := readAggTestCounter.Add(1)
	dsn := fmt.Sprintf("file:kxreadagg_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
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
