// local_audit_search_test.go — integration tests for the new AuditFilter fields
// (IPAddress, ActorUsername, ResourceType) exercised against a real in-memory
// SQLite database so the GORM predicates are actually evaluated.
package store

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var auditSearchTestCounter atomic.Int64

// newAuditSearchStore opens a uniquely-named in-memory SQLite DB and migrates
// audit_events + users (needed for the ActorUsername subquery join).
func newAuditSearchStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	n := auditSearchTestCounter.Add(1)
	dsn := fmt.Sprintf("file:kxauditsearch_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
	))
	return NewLocalStorage(db), db
}

// seedAuditEvent inserts an AuditEvent and returns its ID.
func seedAuditEvent(t *testing.T, db *gorm.DB, e *models.AuditEvent) uint {
	t.Helper()
	require.NoError(t, db.Create(e).Error)
	return e.ID
}


// ── IPAddress filter ──────────────────────────────────────────────────────────

func TestGetAuditLogs_FilterByIPAddress(t *testing.T) {
	ls, db := newAuditSearchStore(t)
	tru := true
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", IPAddress: "10.0.0.1", Success: &tru, EventTime: time.Now(),
	})
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", IPAddress: "192.168.1.1", Success: &tru, EventTime: time.Now(),
	})

	ip := "10.0.0.1"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		IPAddress: &ip,
		PageSize:  50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, events, 1)
	assert.Equal(t, "10.0.0.1", events[0].IPAddress)
}

// ── no match for IPAddress → empty ───────────────────────────────────────────

func TestGetAuditLogs_FilterByIPAddress_NoMatch(t *testing.T) {
	ls, db := newAuditSearchStore(t)
	tru := true
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", IPAddress: "10.0.0.2", Success: &tru, EventTime: time.Now(),
	})

	ip := "99.99.99.99"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		IPAddress: &ip,
		PageSize:  50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, events)
}

// ── ActorUsername filter via users subquery ────────────────────────────────────

func TestGetAuditLogs_FilterByActorUsername(t *testing.T) {
	ls, db := newAuditSearchStore(t)

	// Seed a user named "alice".
	alice := &models.User{Username: "alice", Email: "alice@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(alice).Error)

	tru := true
	// Alice's event.
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", UserID: &alice.ID, Success: &tru, EventTime: time.Now(),
	})
	// Unrelated event with no user.
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "user.login", Success: &tru, EventTime: time.Now(),
	})

	actor := "alice"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		ActorUsername: &actor,
		PageSize:      50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, events, 1)
	assert.Equal(t, alice.ID, *events[0].UserID)
}

// ── partial ActorUsername match ────────────────────────────────────────────────

func TestGetAuditLogs_FilterByActorUsername_Partial(t *testing.T) {
	ls, db := newAuditSearchStore(t)

	alice := &models.User{Username: "alice.smith", Email: "alice.smith@example.com", PasswordHash: "x"}
	bob := &models.User{Username: "bob", Email: "bob@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(alice).Error)
	require.NoError(t, db.Create(bob).Error)

	tru := true
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", UserID: &alice.ID, Success: &tru, EventTime: time.Now(),
	})
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "user.login", UserID: &bob.ID, Success: &tru, EventTime: time.Now(),
	})

	// "alice" should partially match "alice.smith" but not "bob".
	actor := "alice"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		ActorUsername: &actor,
		PageSize:      50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, events, 1)
	assert.Equal(t, alice.ID, *events[0].UserID)
}

// ── ActorUsername with no matching user → empty ───────────────────────────────

func TestGetAuditLogs_FilterByActorUsername_NoMatch(t *testing.T) {
	ls, db := newAuditSearchStore(t)
	tru := true
	uid := uint(999)
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", UserID: &uid, Success: &tru, EventTime: time.Now(),
	})

	actor := "nonexistent"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		ActorUsername: &actor,
		PageSize:      50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, events)
}

// ── ResourceType filter ────────────────────────────────────────────────────────

func TestGetAuditLogs_FilterByResourceType(t *testing.T) {
	ls, db := newAuditSearchStore(t)
	tru := true
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", Success: &tru, EventTime: time.Now(),
	})
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.created", Success: &tru, EventTime: time.Now(),
	})
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "user.login", Success: &tru, EventTime: time.Now(),
	})

	rt := "secret"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		ResourceType: &rt,
		PageSize:     50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, events, 2)
	for _, e := range events {
		assert.Contains(t, e.EventType, "secret.")
	}
}

// ── ResourceType with no match → empty ────────────────────────────────────────

func TestGetAuditLogs_FilterByResourceType_NoMatch(t *testing.T) {
	ls, db := newAuditSearchStore(t)
	tru := true
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "user.login", Success: &tru, EventTime: time.Now(),
	})

	rt := "role"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		ResourceType: &rt,
		PageSize:     50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, events)
}

// ── Combined: IPAddress + ResourceType ────────────────────────────────────────

func TestGetAuditLogs_FilterCombined_IPAndResourceType(t *testing.T) {
	ls, db := newAuditSearchStore(t)
	tru := true
	// Match: secret read from 10.0.0.1
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", IPAddress: "10.0.0.1", Success: &tru, EventTime: time.Now(),
	})
	// No match: user login from 10.0.0.1
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "user.login", IPAddress: "10.0.0.1", Success: &tru, EventTime: time.Now(),
	})
	// No match: secret read from different IP
	seedAuditEvent(t, db, &models.AuditEvent{
		EventType: "secret.read", IPAddress: "1.2.3.4", Success: &tru, EventTime: time.Now(),
	})

	ip := "10.0.0.1"
	rt := "secret"
	events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{
		IPAddress:    &ip,
		ResourceType: &rt,
		PageSize:     50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, events, 1)
	assert.Equal(t, "secret.read", events[0].EventType)
	assert.Equal(t, "10.0.0.1", events[0].IPAddress)
}

// ── Nil filter still works (smoke) ────────────────────────────────────────────

func TestGetAuditLogs_NilFilter_AuditSearch(t *testing.T) {
	ls, _ := newAuditSearchStore(t)
	events, total, err := ls.GetAuditLogs(context.Background(), nil)
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, events)
}
