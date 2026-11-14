package core

// break_glass_posture_consistency_test.go — BREAKGLASS-POSTURE-NOV-1 item 2:
// the three consumers of "which break-glass activations are owed a review" must
// agree on one fixture, on a real store:
//
//   - the compliance posture rollup (accumulateBreakGlassPosture, fed the way
//     GetCompliancePosture feeds it, from ListBreakGlassActivations);
//   - the review-reminder scheduler (RunBreakGlassReviewReminder);
//   - the status surface behind GET /api/v1/system/info security.break_glass_degraded
//     (BreakGlassDegradedStatus), which reports the DEGRADED subset.
//
// The posture once ignored a fresh degraded activation (item 1) while the other two
// listed it; a count that differs between surfaces is a compliance report that
// contradicts itself.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestBreakGlassReviewOwed_PostureReminderAndStatusAgree(t *testing.T) {
	f := newCTAReviewSQLite(t)
	c := f.coreA
	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, ReviewWindow: 72 * time.Hour})
	now := time.Now().UTC()
	c.now = func() time.Time { return now }

	mk := func(name string, created time.Time, degraded, reviewed bool) uint {
		t.Helper()
		u := f.user(name, "project_viewer")
		a := &models.BreakGlassActivation{
			ProjectID: f.projectID, UserID: u.ID, RoleName: "project_developer",
			Justification: "consistency fixture", State: BreakGlassRevoked,
			CreatedAt: created, Degraded: degraded,
		}
		if reviewed {
			at := created.Add(time.Minute)
			a.ReviewedBy, a.ReviewedAt = f.adminID, &at
		}
		require.NoError(t, f.dbA.Create(a).Error)
		return a.ID
	}
	degradedFresh := mk("bgc-degraded-fresh", now.Add(-time.Minute), true, false)
	_ = mk("bgc-normal-fresh", now.Add(-time.Minute), false, false)
	normalOverdue := mk("bgc-normal-overdue", now.Add(-100*time.Hour), false, false)
	_ = mk("bgc-reviewed", now.Add(-200*time.Hour), false, true)

	// The one fact: a degraded activation is owed a review at once, a normal one
	// only past the window, a reviewed one never.
	wantIDs := []uint{degradedFresh, normalOverdue}

	// Posture rollup.
	acts, err := c.ListBreakGlassActivations(f.ctx, f.projectID)
	require.NoError(t, err)
	p := &CompliancePosture{}
	c.accumulateBreakGlassPosture(p, f.projectID, &complianceSnapshot{
		breakGlassByProject:    map[uint][]*models.BreakGlassActivation{f.projectID: acts},
		breakGlassErrByProject: map[uint]error{},
	})
	assert.Equal(t, 4, p.EmergencyAccess.TotalActivations)
	assert.Equal(t, len(wantIDs), p.EmergencyAccess.UnreviewedActivations, "posture rollup")
	assert.Equal(t, 100, p.EmergencyAccess.OldestUnreviewedAgeHours, "posture oldest age")

	// Review reminder: the rows it acts on, and the count it returns.
	rows, err := c.ListUnreviewedBreakGlassActivations(f.ctx, c.breakGlassReviewWindow())
	require.NoError(t, err)
	var gotIDs []uint
	degradedInRows := 0
	for _, a := range rows {
		gotIDs = append(gotIDs, a.ID)
		if a.Degraded {
			degradedInRows++
		}
	}
	assert.ElementsMatch(t, wantIDs, gotIDs, "review reminder's list")
	n, err := c.RunBreakGlassReviewReminder(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, p.EmergencyAccess.UnreviewedActivations, n, "reminder count must equal the posture count")

	// Status surface: the degraded subset of the same list.
	st := c.BreakGlassDegradedStatus(f.ctx)
	assert.Equal(t, int64(degradedInRows), st.Unreviewed, "status degraded-unreviewed count")
	assert.Equal(t, []uint{degradedFresh}, st.ActivationIDs, "status lists the degraded activation, not the normal overdue one")
}
