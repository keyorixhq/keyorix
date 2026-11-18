package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestEvaluateControls_EmergencyAccessDegradedActivationTable is
// POSTURE-CONSUMERS-NOV-1 item 3. Decision (kept from #4248 review F1, no code
// change): a degraded break-glass activation makes the emergency-access control
// a Gap for exactly as long as it is unreviewed. Its audit rows are owed and the
// independent review that stands in for them has not happened, so the control
// cannot be Pass. A reviewed one is no longer a Gap, but while its audit rows
// are still owed the audit record is incomplete, so the control is Unknown and
// not Pass. Only a reviewed and settled one is back to Pass.
//
// The posture comes from the real accumulateBreakGlassPosture, so the pairing
// of owed-audit reason and unreviewed count is the one production emits.
func TestEvaluateControls_EmergencyAccessDegradedActivationTable(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	reviewed := fixed.Add(-time.Minute)
	settled := fixed.Add(-time.Minute)

	tests := []struct {
		name       string
		act        *models.BreakGlassActivation
		want       ControlStatus
		wantDetail string
	}{
		{
			name:       "healthy: normal activation, reviewed",
			act:        &models.BreakGlassActivation{ID: 1, ProjectID: 1, State: BreakGlassRevoked, CreatedAt: fixed.Add(-time.Hour), ReviewedAt: &reviewed},
			want:       ControlStatusPass,
			wantDetail: "all audited",
		},
		{
			name:       "degraded, unreviewed, audit rows owed",
			act:        &models.BreakGlassActivation{ID: 2, ProjectID: 1, State: BreakGlassActive, CreatedAt: fixed.Add(-time.Minute), Degraded: true},
			want:       ControlStatusGap,
			wantDetail: "1 with audit rows still owed",
		},
		{
			name:       "degraded, unreviewed, audit rows settled",
			act:        &models.BreakGlassActivation{ID: 3, ProjectID: 1, State: BreakGlassRevoked, CreatedAt: fixed.Add(-time.Hour), Degraded: true, AuditSettledAt: &settled},
			want:       ControlStatusGap,
			wantDetail: "1 unreviewed past the window",
		},
		{
			name:       "degraded, reviewed, audit rows still owed",
			act:        &models.BreakGlassActivation{ID: 4, ProjectID: 1, State: BreakGlassRevoked, CreatedAt: fixed.Add(-time.Hour), Degraded: true, ReviewedAt: &reviewed},
			want:       ControlStatusUnknown,
			wantDetail: "1 with audit rows still owed",
		},
		{
			name:       "degraded, reviewed, audit rows settled",
			act:        &models.BreakGlassActivation{ID: 5, ProjectID: 1, State: BreakGlassRevoked, CreatedAt: fixed.Add(-time.Hour), Degraded: true, ReviewedAt: &reviewed, AuditSettledAt: &settled},
			want:       ControlStatusPass,
			wantDetail: "all audited",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := NewKeyorixCore(new(MockStorage))
			c.now = func() time.Time { return fixed }
			c.SetBreakGlassPolicy(BreakGlassPolicy{ReviewWindow: 72 * time.Hour})

			p := &CompliancePosture{}
			c.accumulateBreakGlassPosture(p, 1, &complianceSnapshot{
				breakGlassByProject:    map[uint][]*models.BreakGlassActivation{1: {tt.act}},
				breakGlassErrByProject: map[uint]error{},
			})

			ctrl := findControl(t, EvaluateControls(p), "emergency-access")
			assert.Equal(t, tt.want, ctrl.Status, "detail: %s", ctrl.Detail)
			assert.Contains(t, ctrl.Detail, tt.wantDetail)
		})
	}
}
