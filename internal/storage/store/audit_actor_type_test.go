package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// #2951 item 1: the actor_type filter must agree with the kind the API displays.
// A row with no acting user is displayed as kind "system" (actor "system") even
// when it stores the column default "user" or a legacy empty value, so
// actor_type=system must find it and actor_type=user must not.
func TestGetAuditLogs_ActorTypeFilterMatchesDisplayedKind(t *testing.T) {
	ctx := context.Background()
	ls := newAuditTestStore(t)
	now := time.Now().UTC()
	uid := uint(5)

	add := func(eventType, actorType string, userID *uint, at time.Time) {
		t.Helper()
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: eventType, ActorType: actorType, UserID: userID, EventTime: at}))
	}
	add("secret.read", "user", &uid, now.Add(1*time.Second))                 // human
	add("secret.auto_rotate_completed", "user", nil, now.Add(2*time.Second)) // default-user, no actor => system
	add("anomaly.detected", "system", nil, now.Add(3*time.Second))           // explicit system
	add("secret.read", "machine_identity", nil, now.Add(4*time.Second))      // machine
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, event_time) VALUES ('legacy.sys', '', ?)", now.Add(5*time.Second)).Error)
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('legacy.user', '', ?, ?)", uid, now.Add(6*time.Second)).Error)

	types := func(kind string) []string {
		t.Helper()
		events, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorType: &kind, Ascending: true})
		require.NoError(t, err)
		out := make([]string, 0, len(events))
		for _, e := range events {
			out = append(out, e.EventType)
		}
		return out
	}
	assert.Equal(t, []string{"secret.auto_rotate_completed", "anomaly.detected", "legacy.sys"}, types("system"))
	assert.Equal(t, []string{"secret.read", "legacy.user"}, types("user"))
	assert.Equal(t, []string{"secret.read"}, types("machine_identity"))
}

// #2951 item 1: the actor (username) filter must find system events. Their actor
// is displayed as "system" (no user row exists), so searching for it must match
// rows with no acting user, alongside any real user whose name contains the term.
func TestGetAuditLogs_ActorFilterFindsSystemEvents(t *testing.T) {
	ctx := context.Background()
	ls := newAuditTestStore(t)
	require.NoError(t, ls.db.AutoMigrate(&models.User{}))
	now := time.Now().UTC()

	alice := &models.User{Username: "alice", Email: "a@example.com"}
	require.NoError(t, ls.db.Create(alice).Error)
	uid := alice.ID

	require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "secret.read", ActorType: "user", UserID: &uid, EventTime: now.Add(time.Second)}))
	require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "secret.auto_rotate_completed", ActorType: "user", EventTime: now.Add(2 * time.Second)}))
	require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "anomaly.detected", ActorType: "system", EventTime: now.Add(3 * time.Second)}))

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
	assert.Equal(t, []string{"secret.auto_rotate_completed", "anomaly.detected"}, find("system"))
	assert.Equal(t, []string{"secret.auto_rotate_completed", "anomaly.detected"}, find("SYS"), "partial, case-insensitive like the username match")
	assert.Equal(t, []string{"secret.read"}, find("alice"), "a real username must not pull in system events")
}
