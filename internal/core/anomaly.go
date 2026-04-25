package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AnomalyDetector detects anomalous secret access patterns using statistical baselines.
// Operates on metadata only — secret values are never examined.
type AnomalyDetector struct {
	storage StorageInterface
}

// StorageInterface is satisfied by *storage.LocalStorage and *storage.RemoteStorage.
type StorageInterface = interface {
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, unacknowledgedOnly bool) ([]models.AnomalyAlert, error)
	AcknowledgeAnomalyAlert(ctx context.Context, id uint) error
}

// NewAnomalyDetector creates a new AnomalyDetector.
func NewAnomalyDetector(storage StorageInterface) *AnomalyDetector {
	return &AnomalyDetector{storage: storage}
}

// accessBaseline holds statistical baseline for a secret's access patterns.
type accessBaseline struct {
	knownIPs   map[string]bool
	knownUsers map[string]bool
	dailyAvg   float64 // average accesses per day over last 7 days
}

// RunDetection analyses SecretAccessLog for the past hour and emits AnomalyAlert rows.
// Safe to call on a schedule — idempotent per detection window.
func (d *AnomalyDetector) RunDetection(ctx context.Context, secrets []models.SecretNode) error {
	now := time.Now().UTC()
	window := now.Add(-1 * time.Hour)
	baselineWindow := now.Add(-30 * 24 * time.Hour)

	for _, secret := range secrets {
		// Build 30-day baseline
		baselineLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, baselineWindow)
		if err != nil {
			continue
		}
		if len(baselineLogs) == 0 {
			continue
		}
		baseline := buildBaseline(baselineLogs, now)

		// Get recent accesses (last hour)
		recentLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, window)
		if err != nil {
			continue
		}

		for _, accessLog := range recentLogs {
			alerts := detectAnomalies(secret, accessLog, baseline)
			for _, alert := range alerts {
				_ = d.storage.CreateAnomalyAlert(ctx, &alert)
			}
		}
	}
	return nil
}

// buildBaseline computes statistical baseline from historical access logs.
func buildBaseline(logs []models.SecretAccessLog, now time.Time) accessBaseline {
	b := accessBaseline{
		knownIPs:   make(map[string]bool),
		knownUsers: make(map[string]bool),
	}
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)
	recentCount := 0

	for _, log := range logs {
		if log.IPAddress != "" {
			b.knownIPs[log.IPAddress] = true
		}
		if log.AccessedBy != "" {
			b.knownUsers[log.AccessedBy] = true
		}
		if log.AccessTime.After(sevenDaysAgo) {
			recentCount++
		}
	}
	b.dailyAvg = float64(recentCount) / 7.0
	return b
}

// detectAnomalies checks a single access log entry against the baseline.
func detectAnomalies(secret models.SecretNode, log models.SecretAccessLog, baseline accessBaseline) []models.AnomalyAlert {
	var alerts []models.AnomalyAlert
	now := time.Now().UTC()

	// Rule 1: Off-hours access (22:00 - 06:00 UTC)
	hour := log.AccessTime.UTC().Hour()
	if hour >= 22 || hour < 6 {
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "off_hours",
			Severity:     "medium",
			Description:  fmt.Sprintf("Secret accessed outside business hours at %s UTC", log.AccessTime.UTC().Format("15:04")),
			AccessedBy:   log.AccessedBy,
			IPAddress:    log.IPAddress,
			DetectedAt:   now,
		})
	}

	// Rule 2: Access from unknown IP
	if log.IPAddress != "" && !baseline.knownIPs[log.IPAddress] && len(baseline.knownIPs) > 0 {
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "new_ip",
			Severity:     "high",
			Description:  fmt.Sprintf("Secret accessed from unrecognised IP address: %s", log.IPAddress),
			AccessedBy:   log.AccessedBy,
			IPAddress:    log.IPAddress,
			DetectedAt:   now,
		})
	}

	// Rule 3: Access by unknown user
	if log.AccessedBy != "" && !baseline.knownUsers[log.AccessedBy] && len(baseline.knownUsers) > 0 {
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "new_user",
			Severity:     "high",
			Description:  fmt.Sprintf("Secret accessed by user with no prior access history: %s", log.AccessedBy),
			AccessedBy:   log.AccessedBy,
			IPAddress:    log.IPAddress,
			DetectedAt:   now,
		})
	}

	return alerts
}

// ListAlerts returns anomaly alerts, optionally filtering to unacknowledged only.
func (d *AnomalyDetector) ListAlerts(ctx context.Context, unacknowledgedOnly bool) ([]models.AnomalyAlert, error) {
	return d.storage.ListAnomalyAlerts(ctx, unacknowledgedOnly)
}

// AcknowledgeAlert marks an alert as acknowledged.
func (d *AnomalyDetector) AcknowledgeAlert(ctx context.Context, id uint) error {
	return d.storage.AcknowledgeAnomalyAlert(ctx, id)
}
