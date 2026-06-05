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

	ev := func(eventType, actorType string, at time.Time) *models.AuditEvent {
		return &models.AuditEvent{EventType: eventType, ActorType: actorType, EventTime: at}
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
