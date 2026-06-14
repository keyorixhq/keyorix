package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AlertNewAnomalies pushes each not-yet-alerted anomaly out (audit/SIEM event +
// admin notify), marks it alerted, and is idempotent on a second pass.
func TestAlertNewAnomalies(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AnomalyAlert{}, &models.AuditEvent{}, &models.SecretNode{}))

	ctx := context.Background()
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 500, ProjectID: 2, Name: "db-pw", Status: "active", IsSecret: true}).Error)
	require.NoError(t, h.DB.Create(&models.AnomalyAlert{
		SecretNodeID: 500, SecretName: "db-pw", AlertType: "new_ip", Severity: "high",
		Description: "access from a new IP", AccessedBy: "alice", IPAddress: "203.0.113.9",
		DetectedAt: time.Now(),
	}).Error)

	n, err := h.CoreService.AlertNewAnomalies(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// A security.anomaly_detected audit event was emitted (flows to SIEM).
	var events int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAnomalyDetected).Count(&events).Error)
	assert.Equal(t, int64(1), events)

	// Idempotent — a second pass announces nothing.
	n, err = h.CoreService.AlertNewAnomalies(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// The compliance posture counts open (unacknowledged) anomalies, with a high-severity tally.
func TestCompliancePosture_Anomalies(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AnomalyAlert{}, &models.SecretNode{}, &models.AuditEvent{}, &models.AccessReviewCampaign{},
		&models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{}, &models.SoDPolicy{},
	))

	ctx := context.Background()
	require.NoError(t, h.DB.Create(&models.AnomalyAlert{AlertType: "new_ip", Severity: "high", DetectedAt: time.Now()}).Error)
	require.NoError(t, h.DB.Create(&models.AnomalyAlert{AlertType: "off_hours", Severity: "medium", DetectedAt: time.Now()}).Error)
	require.NoError(t, h.DB.Create(&models.AnomalyAlert{AlertType: "new_user", Severity: "high", Acknowledged: true, DetectedAt: time.Now()}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, p.Anomalies.Unacknowledged, "two open alerts (the acknowledged one excluded)")
	assert.Equal(t, 1, p.Anomalies.HighSeverityOpen, "one of the open alerts is high severity")
}
