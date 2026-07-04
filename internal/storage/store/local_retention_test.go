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

func newRetentionTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AnomalyAlert{},
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
	))
	return NewLocalStorage(db)
}

func TestDeleteAnomalyAlertsBefore(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{ID: 1, DetectedAt: now.AddDate(0, 0, -40)}).Error)
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{ID: 2, DetectedAt: now.AddDate(0, 0, -5)}).Error)

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "neither alert is acknowledged, so nothing is purged regardless of age")

	var remaining int64
	require.NoError(t, ls.db.Model(&models.AnomalyAlert{}).Count(&remaining).Error)
	assert.Equal(t, int64(2), remaining)
}

// #415: a never-acknowledged alert is a live, unreviewed security signal — it must
// survive age-based purge even when well past the retention window. Only an
// already-acknowledged alert is eligible for deletion once it's old enough.
func TestDeleteAnomalyAlertsBefore_SkipsUnacknowledged(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 1, DetectedAt: now.AddDate(0, 0, -40), Acknowledged: true,
	}).Error)
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 2, DetectedAt: now.AddDate(0, 0, -40), Acknowledged: false,
	}).Error)

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "only the acknowledged, old alert is purged")

	var remaining models.AnomalyAlert
	require.NoError(t, ls.db.Where("id = ?", 2).First(&remaining).Error)
	assert.False(t, remaining.Acknowledged)

	var count int64
	require.NoError(t, ls.db.Model(&models.AnomalyAlert{}).Where("id = ?", 1).Count(&count).Error)
	assert.Equal(t, int64(0), count, "the acknowledged alert must be gone")
}

func TestDeleteClosedAccessReviewsBefore_CascadesItemsAndSkipsOpen(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now()
	oldClosed := now.AddDate(0, 0, -400)
	recentClosed := now.AddDate(0, 0, -10)

	// Campaign 1: closed long ago, with 2 items — should be purged with its items.
	require.NoError(t, ls.db.Create(&models.AccessReviewCampaign{ID: 1, State: "closed", ClosedAt: &oldClosed}).Error)
	require.NoError(t, ls.db.Create(&models.AccessReviewItem{ID: 10, CampaignID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.AccessReviewItem{ID: 11, CampaignID: 1}).Error)
	// Campaign 2: closed recently — within window, kept.
	require.NoError(t, ls.db.Create(&models.AccessReviewCampaign{ID: 2, State: "closed", ClosedAt: &recentClosed}).Error)
	require.NoError(t, ls.db.Create(&models.AccessReviewItem{ID: 20, CampaignID: 2}).Error)
	// Campaign 3: OPEN (closed_at NULL) even though created long ago — never purged.
	require.NoError(t, ls.db.Create(&models.AccessReviewCampaign{ID: 3, State: "open", CreatedAt: oldClosed}).Error)
	require.NoError(t, ls.db.Create(&models.AccessReviewItem{ID: 30, CampaignID: 3}).Error)

	camps, items, err := ls.DeleteClosedAccessReviewsBefore(ctx, now.AddDate(0, 0, -365))
	require.NoError(t, err)
	assert.Equal(t, int64(1), camps, "only the old closed campaign is purged")
	assert.Equal(t, int64(2), items, "its two snapshot items cascade")

	var campCount, itemCount int64
	require.NoError(t, ls.db.Model(&models.AccessReviewCampaign{}).Count(&campCount).Error)
	require.NoError(t, ls.db.Model(&models.AccessReviewItem{}).Count(&itemCount).Error)
	assert.Equal(t, int64(2), campCount, "recent-closed + open campaigns remain")
	assert.Equal(t, int64(2), itemCount, "items of the recent + open campaigns remain")
}

func TestDeleteExpiredBreakGlassBefore_SkipsActive(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -120)

	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{ID: 1, State: "expired", CreatedAt: old}).Error)
	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{ID: 2, State: "revoked", CreatedAt: old}).Error)
	// Still active despite being old — must never be purged.
	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{ID: 3, State: "active", CreatedAt: old}).Error)

	n, err := ls.DeleteExpiredBreakGlassBefore(ctx, time.Now().AddDate(0, 0, -90))
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "expired + revoked purged, active kept")

	var active int64
	require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).Where("state = ?", "active").Count(&active).Error)
	assert.Equal(t, int64(1), active)
}

func TestDeleteResolvedAccessRequestsBefore_CascadesAndSkipsPending(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now()
	oldResolved := now.AddDate(0, 0, -200)

	// Resolved request with 2 approvals (from 2 distinct approvers) — purged with them.
	require.NoError(t, ls.db.Create(&models.AccessRequest{ID: 1, State: "approved", ResolvedAt: &oldResolved}).Error)
	require.NoError(t, ls.db.Create(&models.AccessRequestApproval{ID: 100, RequestID: 1, ApproverID: 11}).Error)
	require.NoError(t, ls.db.Create(&models.AccessRequestApproval{ID: 101, RequestID: 1, ApproverID: 12}).Error)
	// Pending request (resolved_at NULL) created long ago — never purged.
	require.NoError(t, ls.db.Create(&models.AccessRequest{ID: 2, State: "pending", CreatedAt: oldResolved}).Error)

	reqs, appr, err := ls.DeleteResolvedAccessRequestsBefore(ctx, now.AddDate(0, 0, -180))
	require.NoError(t, err)
	assert.Equal(t, int64(1), reqs)
	assert.Equal(t, int64(2), appr)

	var reqCount, apprCount int64
	require.NoError(t, ls.db.Model(&models.AccessRequest{}).Count(&reqCount).Error)
	require.NoError(t, ls.db.Model(&models.AccessRequestApproval{}).Count(&apprCount).Error)
	assert.Equal(t, int64(1), reqCount, "the pending request remains")
	assert.Equal(t, int64(0), apprCount, "approvals of the purged request are gone")
}
