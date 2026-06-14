package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPurgeExpiredComplianceRecords_CountsCutoffsAndAudits(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	policy := RetentionPolicy{
		AnomalyAlertsDays:          30,
		ClosedAccessReviewsDays:    365,
		BreakGlassDays:             90,
		ResolvedAccessRequestsDays: 180,
	}
	store := new(MockStorage)
	store.On("DeleteAnomalyAlertsBefore", mock.Anything, now.AddDate(0, 0, -30)).Return(int64(5), nil)
	store.On("DeleteClosedAccessReviewsBefore", mock.Anything, now.AddDate(0, 0, -365)).Return(int64(2), int64(7), nil)
	store.On("DeleteExpiredBreakGlassBefore", mock.Anything, now.AddDate(0, 0, -90)).Return(int64(1), nil)
	store.On("DeleteResolvedAccessRequestsBefore", mock.Anything, now.AddDate(0, 0, -180)).Return(int64(3), int64(4), nil)

	var actor string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		if e.EventType == "data.retention_purged" {
			actor = e.ActorType
			return true
		}
		return false
	})).Return(nil)

	c := NewKeyorixCore(store)
	res, err := c.PurgeExpiredComplianceRecords(context.Background(), now, policy)
	require.NoError(t, err)
	require.Equal(t, int64(5), res.AnomalyAlerts)
	require.Equal(t, int64(2), res.ClosedAccessReviews)
	require.Equal(t, int64(7), res.AccessReviewItems)
	require.Equal(t, int64(1), res.BreakGlass)
	require.Equal(t, int64(3), res.ResolvedAccessRequests)
	require.Equal(t, int64(4), res.AccessRequestApprovals)
	require.Equal(t, int64(22), res.Total())
	require.Equal(t, ActorTypeSystem, actor, "retention purge is actored as system")
	store.AssertExpectations(t)
}

func TestPurgeExpiredComplianceRecords_ZeroWindowsSkipped(t *testing.T) {
	now := time.Now()
	// Only break-glass has a window; every other type is keep-forever (0).
	policy := RetentionPolicy{BreakGlassDays: 45}
	store := new(MockStorage)
	store.On("DeleteExpiredBreakGlassBefore", mock.Anything, mock.Anything).Return(int64(0), nil)

	c := NewKeyorixCore(store)
	res, err := c.PurgeExpiredComplianceRecords(context.Background(), now, policy)
	require.NoError(t, err)
	require.Equal(t, int64(0), res.Total())

	// Disabled types are never queried, and a zero-purge run emits no audit event.
	store.AssertNotCalled(t, "DeleteAnomalyAlertsBefore", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "DeleteClosedAccessReviewsBefore", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "DeleteResolvedAccessRequestsBefore", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

func TestRetentionPolicy_Configured(t *testing.T) {
	require.False(t, RetentionPolicy{}.Configured())
	require.True(t, RetentionPolicy{AnomalyAlertsDays: 1}.Configured())
	require.True(t, RetentionPolicy{ResolvedAccessRequestsDays: 90}.Configured())
}
