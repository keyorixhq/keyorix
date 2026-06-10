package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPurgeExpiredSoftDeletes_CountsAndAudits(t *testing.T) {
	before := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("PurgeDeletedUsersBefore", mock.Anything, before).Return(int64(2), nil)
	store.On("PurgeDeletedProjectsBefore", mock.Anything, before).Return(int64(1), nil)
	store.On("PurgeDeletedEnvironmentsBefore", mock.Anything, before).Return(int64(3), nil)
	store.On("PurgeDeletedSecretsBefore", mock.Anything, before).Return(int64(4), nil)

	// Something was purged → a single system-actored data.purged event is written.
	var auditedActorType string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		if e.EventType == "data.purged" {
			auditedActorType = e.ActorType
			return true
		}
		return false
	})).Return(nil)

	c := NewKeyorixCore(store)
	res, err := c.PurgeExpiredSoftDeletes(context.Background(), before)
	require.NoError(t, err)
	require.Equal(t, int64(2), res.Users)
	require.Equal(t, int64(1), res.Projects)
	require.Equal(t, int64(3), res.Environments)
	require.Equal(t, int64(4), res.Secrets)
	require.Equal(t, int64(10), res.Total())
	require.Equal(t, ActorTypeSystem, auditedActorType, "purge is actored as system")
}

func TestPurgeExpiredSoftDeletes_NoAuditWhenNothingPurged(t *testing.T) {
	before := time.Now()
	store := new(MockStorage)
	store.On("PurgeDeletedUsersBefore", mock.Anything, before).Return(int64(0), nil)
	store.On("PurgeDeletedProjectsBefore", mock.Anything, before).Return(int64(0), nil)
	store.On("PurgeDeletedEnvironmentsBefore", mock.Anything, before).Return(int64(0), nil)
	store.On("PurgeDeletedSecretsBefore", mock.Anything, before).Return(int64(0), nil)
	// No LogAuditEvent expectation: a zero-purge run must not emit an event.

	c := NewKeyorixCore(store)
	res, err := c.PurgeExpiredSoftDeletes(context.Background(), before)
	require.NoError(t, err)
	require.Equal(t, int64(0), res.Total())
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}
