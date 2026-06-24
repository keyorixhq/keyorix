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

// A secret read recorded through the real production logging path
// (LogSecretReadWithProject → writeAccessLog → CreateSecretAccessLog) must be
// visible to anomaly detection. Both the HTTP reveal handler and the gRPC
// GetSecretValue fire that exact call, so this guards the end-to-end pipeline:
// the existing detector tests hand-build SecretAccessLog rows, which would not
// catch the writer drifting (action string, field mapping) and silently
// re-blinding detection to real reads.
func TestLogSecretRead_FeedsAnomalyDetection(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.SecretNode{}, &models.SecretAccessLog{}, &models.AnomalyAlert{}, &models.AuditEvent{}))

	ctx := context.Background()
	secret := models.SecretNode{ID: 700, ProjectID: 1, Name: "api-key", Status: "active", IsSecret: true}
	require.NoError(t, h.DB.Create(&secret).Error)

	// A quiet baseline so the detector has history to compare against (a couple of reads
	// >7 days ago — far below the spike threshold). Seeded directly because the
	// production writer always stamps AccessTime=now, so history can't go through it.
	for i := 8; i <= 10; i++ {
		require.NoError(t, h.DB.Create(&models.SecretAccessLog{
			SecretNodeID: 700, AccessedBy: "alice", Action: "read", IPAddress: "10.0.0.1",
			AccessTime: time.Now().Add(-time.Duration(i) * 24 * time.Hour),
		}).Error)
	}

	// A burst of reads in the detection window, each recorded through the SAME call HTTP
	// and gRPC use (LogSecretReadWithProject → writeAccessLog → CreateSecretAccessLog).
	for i := 0; i < 12; i++ {
		h.CoreService.LogSecretReadWithProject(ctx, 999, 700, 1, "mallory", "api-key", "203.0.113.5", "grpc-go/1.80")
	}

	// Detection must flag the burst as a frequency spike — proving the real logging path
	// lands in secret_access_logs and is counted by the detector, not just hand-built rows.
	detector := core.NewAnomalyDetector(h.CoreService.Storage())
	require.NoError(t, detector.RunDetection(ctx, []models.SecretNode{secret}))

	alerts, err := detector.ListAlerts(ctx, nil)
	require.NoError(t, err)
	var sawSpike bool
	for _, a := range alerts {
		if a.AlertType == "frequency_spike" && a.SecretNodeID == 700 {
			sawSpike = true
		}
	}
	assert.True(t, sawSpike,
		"reads via LogSecretReadWithProject must be visible to anomaly detection")
}

// A first-time access from a never-before-seen user/IP during the detection window
// must raise new_user / new_ip. This regresses the self-poisoning baseline bug: the
// 30-day baseline query overlapped the 1-hour window, so the access being scored was
// itself learned as "known" and the high-severity rules never fired.
func TestRunDetection_FlagsFirstTimeUserAndIP(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.SecretNode{}, &models.SecretAccessLog{}, &models.AnomalyAlert{}, &models.AuditEvent{}))

	ctx := context.Background()
	secret := models.SecretNode{ID: 701, ProjectID: 1, Name: "db-pw", Status: "active", IsSecret: true}
	require.NoError(t, h.DB.Create(&secret).Error)

	// Prior history (2-6 days ago, well before the 1h window): only alice@10.0.0.1.
	for i := 2; i <= 6; i++ {
		require.NoError(t, h.DB.Create(&models.SecretAccessLog{
			SecretNodeID: 701, AccessedBy: "alice", Action: "read", IPAddress: "10.0.0.1",
			AccessTime: time.Now().Add(-time.Duration(i) * 24 * time.Hour),
		}).Error)
	}

	// A read in the detection window from a NEW principal and a NEW IP.
	require.NoError(t, h.DB.Create(&models.SecretAccessLog{
		SecretNodeID: 701, AccessedBy: "mallory", Action: "read", IPAddress: "203.0.113.9",
		AccessTime: time.Now().Add(-2 * time.Minute),
	}).Error)

	detector := core.NewAnomalyDetector(h.CoreService.Storage())
	require.NoError(t, detector.RunDetection(ctx, []models.SecretNode{secret}))

	alerts, err := detector.ListAlerts(ctx, nil)
	require.NoError(t, err)
	var sawNewUser, sawNewIP bool
	for _, a := range alerts {
		if a.SecretNodeID != 701 {
			continue
		}
		switch a.AlertType {
		case "new_user":
			sawNewUser = a.AccessedBy == "mallory"
		case "new_ip":
			sawNewIP = a.IPAddress == "203.0.113.9"
		}
	}
	assert.True(t, sawNewUser, "a first-time user in the window must raise new_user (baseline must exclude the window)")
	assert.True(t, sawNewIP, "a first-time IP in the window must raise new_ip")
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
