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

// testExcludeSystemJobEvents: ExcludeSystemJobEvents hides exactly the
// admin_job.* rows of kind system (#4184). A legacy row with actor_type NULL
// that names a user is kind user, so it stays: under SQL three-valued logic
// `actor_type = 'system'` is NULL for it, and a bare NOT (...) dropped it
// (REVIEW-4192-DEEP-1 LOW).
func testExcludeSystemJobEvents(t *testing.T, ls *LocalStorage) {
	ctx := context.Background()
	now := time.Now().UTC()
	uid := uint(5)
	add := func(e models.AuditEvent, sec int) {
		t.Helper()
		e.EventTime = now.Add(time.Duration(sec) * time.Second)
		require.NoError(t, ls.LogAuditEvent(ctx, &e))
	}
	add(models.AuditEvent{EventType: "admin_job.anomaly_alerts_run", ActorType: "system"}, 1)
	add(models.AuditEvent{EventType: "admin_job.anomaly_alerts_run", ActorType: "user", UserID: &uid}, 2)
	add(models.AuditEvent{EventType: "role.removed", ActorType: "user", UserID: &uid}, 3)
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('admin_job.legacy_user_run', NULL, ?, ?)", uid, now.Add(4*time.Second)).Error)
	require.NoError(t, ls.db.Exec("INSERT INTO audit_events (event_type, actor_type, event_time) VALUES ('admin_job.legacy_system_run', NULL, ?)", now.Add(5*time.Second)).Error)

	events, total, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ExcludeSystemJobEvents: true, Ascending: true})
	require.NoError(t, err)
	got := make([]string, 0, len(events))
	for _, e := range events {
		got = append(got, e.EventType)
		assert.NotEqual(t, "system", storage.AuditActorKind(e), "row %s of kind system must be hidden", e.EventType)
	}
	assert.Equal(t, []string{"admin_job.anomaly_alerts_run", "role.removed", "admin_job.legacy_user_run"}, got)
	assert.EqualValues(t, 3, total, "total must agree with the list")
}

func TestGetAuditLogs_ExcludeSystemJobEvents_KeepsNullActorTypeUserRows(t *testing.T) {
	testExcludeSystemJobEvents(t, newAuditTestStore(t))
}

func TestGetAuditLogs_ExcludeSystemJobEvents_KeepsNullActorTypeUserRows_Postgres(t *testing.T) {
	testExcludeSystemJobEvents(t, newActorKindPGStore(t))
}
