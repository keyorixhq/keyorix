package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAuditTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewLocalStorage(db)
}

// CountImpersonatedActions counts impersonated events for the (actingAs,
// impersonator) pair since a cutoff, excluding the start/end markers.
func TestCountImpersonatedActions(t *testing.T) {
	ctx := context.Background()
	ls := newAuditTestStore(t)
	now := time.Now().UTC()
	admin, target := uint(1), uint(2)

	ev := func(eventType string, impersonation bool, by, as *uint, at time.Time) *models.AuditEvent {
		return &models.AuditEvent{
			EventType: eventType, Impersonation: impersonation,
			ImpersonatedBy: by, ActingAs: as, EventTime: at,
		}
	}

	// Two genuine actions inside the session.
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", true, &admin, &target, now.Add(1*time.Second))))
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.updated", true, &admin, &target, now.Add(2*time.Second))))
	// The bracket markers must NOT be counted as actions.
	require.NoError(t, ls.LogAuditEvent(ctx, ev("impersonation.start", true, &admin, &target, now)))
	require.NoError(t, ls.LogAuditEvent(ctx, ev("impersonation.end", true, &admin, &target, now.Add(3*time.Second))))
	// A non-impersonated event by the same user must NOT be counted.
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", false, nil, &target, now.Add(1*time.Second))))
	// An action before the cutoff must NOT be counted.
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", true, &admin, &target, now.Add(-time.Hour))))
	// A different impersonator must NOT be counted.
	other := uint(9)
	require.NoError(t, ls.LogAuditEvent(ctx, ev("secret.read", true, &other, &target, now.Add(1*time.Second))))

	n, err := ls.CountImpersonatedActions(ctx, target, admin, now)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "only the two genuine in-window actions should count")
}
