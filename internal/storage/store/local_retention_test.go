package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
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

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, now.AddDate(0, 0, -30), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "neither alert is acknowledged, and the unacked ceiling is disabled (zero), so nothing is purged")

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

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, now.AddDate(0, 0, -30), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "only the acknowledged, old alert is purged; the unacked ceiling is disabled (zero)")

	var remaining models.AnomalyAlert
	require.NoError(t, ls.db.Where("id = ?", 2).First(&remaining).Error)
	assert.False(t, remaining.Acknowledged)

	var count int64
	require.NoError(t, ls.db.Model(&models.AnomalyAlert{}).Where("id = ?", 1).Count(&count).Error)
	assert.Equal(t, int64(0), count, "the acknowledged alert must be gone")
}

// #489: unacknowledged alerts must not accumulate forever. A separate, much more
// generous absolute-age ceiling is a safety net independent of acknowledgment:
// an unacknowledged alert younger than the ceiling survives (preserving the #415
// guarantee that a reasonable operational backlog is never silently discarded),
// but one older than the ceiling is purged (closing the disk-exhaustion / unbounded
// ListAnomalyAlerts-scan surface). An acknowledged alert past the pre-existing,
// much shorter acknowledged-retention window is purged exactly as before.
func TestDeleteAnomalyAlertsBefore_UnackedCeilingSafetyNet(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Unacknowledged, well within the ceiling (e.g. a normal operational review
	// backlog) — must survive.
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 1, DetectedAt: now.AddDate(0, 0, -60), Acknowledged: false,
	}).Error)
	// Unacknowledged, older than the ceiling — truly ancient, almost certainly
	// abandoned — must be purged by the new safety net.
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 2, DetectedAt: now.AddDate(0, 0, -800), Acknowledged: false,
	}).Error)
	// Acknowledged, past the pre-existing (much shorter) acknowledged-retention
	// window but well within the unacked ceiling — must still be purged as before
	// (non-regression), via the acknowledged clause, not the ceiling clause.
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 3, DetectedAt: now.AddDate(0, 0, -40), Acknowledged: true,
	}).Error)
	// Acknowledged, recent — within the acknowledged window — must survive.
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 4, DetectedAt: now.AddDate(0, 0, -5), Acknowledged: true,
	}).Error)

	ackBefore := now.AddDate(0, 0, -30)     // acknowledged-alert retention window
	unackCeiling := now.AddDate(0, 0, -730) // generous absolute-age safety net

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, ackBefore, unackCeiling)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "the ancient-unacknowledged alert and the old-acknowledged alert are purged")

	var remainingIDs []uint
	require.NoError(t, ls.db.Model(&models.AnomalyAlert{}).Order("id").Pluck("id", &remainingIDs).Error)
	assert.Equal(t, []uint{1, 4}, remainingIDs, "the recent-unacknowledged and recent-acknowledged alerts survive")
}

// #489: with the unacked ceiling disabled (zero value), behavior is unchanged from
// pre-#489: an unacknowledged alert survives no matter how old it is.
func TestDeleteAnomalyAlertsBefore_UnackedCeilingDisabledKeepsForever(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		ID: 1, DetectedAt: now.AddDate(-5, 0, 0), Acknowledged: false,
	}).Error)

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, now.AddDate(0, 0, -30), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "unacked ceiling disabled (zero) means unacknowledged alerts are kept forever, as before #489")
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

// TestDeleteExpiredBreakGlassBefore_ReclaimsUnreconciledExpired is #1653
// reopened's regression test: ReconcileExpiredBreakGlassActivation only ever
// reconciles the SAME user's row at their own next activation in the SAME
// project, so a row nobody ever revisits (the user never re-activates, and
// nobody revokes it) stays labeled 'active' in the DB forever otherwise. This
// retention sweep must still reclaim it once genuinely TTL-lapsed AND past
// the cutoff -- while a row that's merely OLD but still genuinely live
// (ExpiresAt in the future) must never be purged, cutoff or not.
//
// FIX-7 (adversarial review run 2): reclaiming an unreconciled-but-expired
// row now takes TWO sweep calls, not one -- the first reconciles it to
// 'expired' without deleting it (closing the race a single reconcile+delete
// statement had with any concurrent operation still expecting to find the
// row), the second deletes it like any other already-terminal old row. See
// DeleteExpiredBreakGlassBefore's doc comment.
func TestDeleteExpiredBreakGlassBefore_ReclaimsUnreconciledExpired(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -120)
	longExpired := old.Add(time.Hour) // TTL lapsed shortly after creation, well before the cutoff below
	stillLive := time.Now().AddDate(1, 0, 0)
	cutoff := time.Now().AddDate(0, 0, -90)

	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{
		ID: 4, State: "active", CreatedAt: old, ExpiresAt: &longExpired,
	}).Error)
	// Genuinely still active (far-future ExpiresAt) despite being old — must
	// never be purged regardless of TTL-lapse reasoning.
	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{
		ID: 5, State: "active", CreatedAt: old, ExpiresAt: &stillLive,
	}).Error)

	n, err := ls.DeleteExpiredBreakGlassBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Zero(t, n, "first sweep only reconciles the unreconciled-but-expired row, doesn't delete it yet")

	var afterFirstSweep []models.BreakGlassActivation
	require.NoError(t, ls.db.Order("id").Find(&afterFirstSweep).Error)
	require.Len(t, afterFirstSweep, 2, "both rows still present after the first sweep")
	assert.Equal(t, "expired", afterFirstSweep[0].State, "row 4 reconciled to expired, not yet deleted")
	assert.Equal(t, "active", afterFirstSweep[1].State, "the still-live row untouched")

	n, err = ls.DeleteExpiredBreakGlassBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "second sweep reclaims the now-reconciled row like any other old terminal row")

	var remaining []models.BreakGlassActivation
	require.NoError(t, ls.db.Find(&remaining).Error)
	require.Len(t, remaining, 1)
	assert.Equal(t, uint(5), remaining[0].ID, "the still-live row must survive")
}

// TestDeleteExpiredBreakGlassBefore_ReconciledRowStillRevocable is FIX-7's
// core proving test: a row the retention sweep JUST reconciled to 'expired'
// must still be revocable by a concurrent/subsequent RevokeBreakGlassActivation
// call, not silently gone. Under the pre-fix behavior (reconcile-and-delete in
// one statement), the row would already be hard-deleted by the time a
// concurrent admin's RevokeBreakGlass reached RevokeBreakGlassActivation
// (having already removed the real RBAC grant via RemoveUserRole first),
// producing ErrBreakGlassNotActive despite the revoke having genuinely taken
// effect -- losing the revoke's own audit trail (LogBreakGlassRevoked is only
// called on success).
func TestDeleteExpiredBreakGlassBefore_ReconciledRowStillRevocable(t *testing.T) {
	ls := newRetentionTestStore(t)
	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -120)
	longExpired := old.Add(time.Hour)
	cutoff := time.Now().AddDate(0, 0, -90)

	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{
		ID: 6, State: "active", CreatedAt: old, ExpiresAt: &longExpired,
	}).Error)

	// One sweep pass: reconciles the row to 'expired' without deleting it.
	n, err := ls.DeleteExpiredBreakGlassBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Zero(t, n)

	// A concurrent (or immediately-following) revoke must still find and
	// transition the row -- RevokeBreakGlassActivation's own WHERE clause
	// already accepts 'expired', but that only helps if the row still EXISTS.
	revokedAt := time.Now()
	require.NoError(t, ls.RevokeBreakGlassActivation(ctx, 6, 1, 0, revokedAt),
		"a row the sweep just reconciled (not yet deleted) must still be revocable")

	var row models.BreakGlassActivation
	require.NoError(t, ls.db.First(&row, 6).Error)
	assert.Equal(t, "revoked", row.State)
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
