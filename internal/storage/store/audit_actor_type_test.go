package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// GetAuditLogs filters by actor_type; a nil filter returns every actor kind.
func TestGetAuditLogs_FilterByActorType(t *testing.T) {
	ctx := context.Background()
	ls := newAuditTestStore(t)
	now := time.Now().UTC()

	uid := uint(1) // user rows carry a real acting user (a user row with none is displayed and filtered as "system", #2951)
	ev := func(eventType, actorType string, at time.Time) *models.AuditEvent {
		return &models.AuditEvent{EventType: eventType, ActorType: actorType, UserID: &uid, EventTime: at}
	}
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", "user", now.Add(1*time.Second))))
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", "user", now.Add(2*time.Second))))
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", "machine_identity", now.Add(3*time.Second))))
	require.NoError(t, ls.LogAuditEvent(ctx, ev("anomaly.detected", "system", now.Add(4*time.Second))))

	machine := "machine_identity"
	events, total, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorType: &machine})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "only the machine-actored event matches")
	require.Len(t, events, 1)
	assert.Equal(t, "machine_identity", events[0].ActorType)

	user := "user"
	_, userTotal, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorType: &user})
	require.NoError(t, err)
	assert.Equal(t, int64(2), userTotal, "two user-actored events match")

	_, allTotal, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(4), allTotal, "no actor_type filter returns every event")
}

// newActorKindPGStore is newAuditTestStore on PostgreSQL in its own schema.
// Skips when KEYORIX_TEST_PG_DSN is unset.
func newActorKindPGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	schema := "audit_actor_kind_test"
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
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewLocalStorage(db)
}

// actorKindRows is one row per shape the actor-kind rule distinguishes (#2951
// review). EventType doubles as the row's label; want is the kind it must show.
func actorKindRows() []struct {
	e    models.AuditEvent
	want string
} {
	uid, zero, mid, admin := uint(5), uint(0), uint(4), uint(9)
	return []struct {
		e    models.AuditEvent
		want string
	}{
		{models.AuditEvent{EventType: "secret.read", ActorType: "user", UserID: &uid}, "user"},
		{models.AuditEvent{EventType: "secret.auto_rotated", ActorType: "user"}, "system"},
		{models.AuditEvent{EventType: "share.expired", ActorType: "user", UserID: &zero}, "system"},
		{models.AuditEvent{EventType: "data.retention_purged", ActorType: "system"}, "system"},
		{models.AuditEvent{EventType: "security.anomaly_detected", ActorType: "system", IPAddress: "203.0.113.9"}, "system"},
		{models.AuditEvent{EventType: "auth.login_failed", ActorType: "user", IPAddress: "198.51.100.7"}, "user"},
		{models.AuditEvent{EventType: "auth.login_failed", ActorType: "user"}, "user"},
		{models.AuditEvent{EventType: "mfa.failed", ActorType: "user"}, "user"},
		{models.AuditEvent{EventType: "secret.bulk_rotate_attempted", ActorType: "user", IPAddress: "192.0.2.1"}, "user"},
		{models.AuditEvent{EventType: "secret.impersonated_read", ActorType: "user", ImpersonatedBy: &admin}, "user"},
		{models.AuditEvent{EventType: "secret.machine_default_row", ActorType: "user", MachineIdentityID: &mid}, "user"},
		{models.AuditEvent{EventType: "secret.machine_read", ActorType: "machine_identity", MachineIdentityID: &mid}, "machine_identity"},
	}
}

// testActorKindFilterAgreesWithDisplay seeds every shape (plus legacy rows with
// actor_type "" written by raw SQL, which LogAuditEvent cannot produce) and
// asserts, for each kind, that actor_type=<kind> returns EXACTLY the rows
// storage.AuditActorKind displays as <kind>: no row is shown as one kind and
// found under another. Both directions: failed logins are under "user" and not
// under "system"; scheduler rows are under "system" and not under "user".
func testActorKindFilterAgreesWithDisplay(t *testing.T, ls *LocalStorage) {
	ctx := context.Background()
	now := time.Now().UTC()
	want := map[string][]string{}
	for i, r := range actorKindRows() {
		e := r.e
		e.EventTime = now.Add(time.Duration(i+1) * time.Second)
		require.Equal(t, r.want, storage.AuditActorKind(&e), "fixture %s: rule and fixture disagree", e.EventType)
		require.NoError(t, ls.LogAuditEvent(ctx, &e))
		want[r.want] = append(want[r.want], e.EventType)
	}
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, event_time) VALUES ('legacy.sys', '', ?)", now.Add(100*time.Second)).Error)
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('legacy.user', '', ?, ?)", 5, now.Add(101*time.Second)).Error)
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, ip_address, event_time) VALUES ('webauthn.failed', '', '', ?)", now.Add(102*time.Second)).Error)
	want["system"] = append(want["system"], "legacy.sys")
	want["user"] = append(want["user"], "legacy.user", "webauthn.failed")

	for _, kind := range []string{"user", "system", "machine_identity"} {
		k := kind
		events, total, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorType: &k, Ascending: true})
		require.NoError(t, err)
		got := make([]string, 0, len(events))
		for _, e := range events {
			got = append(got, e.EventType)
			assert.Equal(t, kind, storage.AuditActorKind(e), "row %s returned by actor_type=%s but displayed as another kind", e.EventType, kind)
		}
		assert.Equal(t, want[kind], got, "actor_type=%s", kind)
		assert.Equal(t, int64(len(want[kind])), total, "actor_type=%s total", kind)
	}
}

func TestAuditActorKindWhere_AgreesWithAuditActorKind(t *testing.T) {
	testActorKindFilterAgreesWithDisplay(t, newAuditTestStore(t))
}

func TestAuditActorKindWhere_AgreesWithAuditActorKind_Postgres(t *testing.T) {
	testActorKindFilterAgreesWithDisplay(t, newActorKindPGStore(t))
}

// testActorSearchFindsSystemRows: the actor (username) search. A term that is
// part of "system" finds exactly the kind-system rows (shown with actor
// "system"); it does not pull in a failed login (no user, kind user) or a
// machine row. A username term matches case-insensitively on every backend.
func testActorSearchFindsSystemRows(t *testing.T, ls *LocalStorage) {
	ctx := context.Background()
	require.NoError(t, ls.db.AutoMigrate(&models.User{}))
	now := time.Now().UTC()

	alice := &models.User{Username: "Alice", Email: "a@example.com"}
	require.NoError(t, ls.db.Create(alice).Error)
	uid, mid := alice.ID, uint(4)

	add := func(e models.AuditEvent, sec int) {
		t.Helper()
		e.EventTime = now.Add(time.Duration(sec) * time.Second)
		require.NoError(t, ls.LogAuditEvent(ctx, &e))
	}
	add(models.AuditEvent{EventType: "secret.read", ActorType: "user", UserID: &uid}, 1)
	add(models.AuditEvent{EventType: "secret.auto_rotated", ActorType: "user"}, 2)
	add(models.AuditEvent{EventType: "data.retention_purged", ActorType: "system"}, 3)
	add(models.AuditEvent{EventType: "auth.login_failed", ActorType: "user", IPAddress: "198.51.100.7"}, 4)
	add(models.AuditEvent{EventType: "secret.machine_read", ActorType: "machine_identity", MachineIdentityID: &mid}, 5)

	find := func(term string) []string {
		t.Helper()
		events, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorUsername: &term, Ascending: true})
		require.NoError(t, err)
		out := make([]string, 0, len(events))
		for _, e := range events {
			out = append(out, e.EventType)
		}
		return out
	}
	assert.Equal(t, []string{"secret.auto_rotated", "data.retention_purged"}, find("system"))
	assert.Equal(t, []string{"secret.auto_rotated", "data.retention_purged"}, find("SYS"), "partial, case-insensitive")
	assert.Equal(t, []string{"secret.read"}, find("alice"), "username match is case-insensitive and does not pull in system rows")
	assert.Equal(t, []string{"secret.read"}, find("LIC"))
}

func TestGetAuditLogs_ActorSearchFindsSystemRows(t *testing.T) {
	testActorSearchFindsSystemRows(t, newAuditTestStore(t))
}

func TestGetAuditLogs_ActorSearchFindsSystemRows_Postgres(t *testing.T) {
	testActorSearchFindsSystemRows(t, newActorKindPGStore(t))
}
