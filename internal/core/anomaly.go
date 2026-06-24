package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AnomalyDetector detects anomalous secret access patterns using statistical baselines
// and, when enabled, an Isolation Forest (ADR-050). Operates on metadata only — secret
// values are never examined.
type AnomalyDetector struct {
	storage StorageInterface
	ml      MLConfig // ML pass; disabled by default (see SetMLConfig)
}

// StorageInterface is satisfied by *storage.LocalStorage and *storage.RemoteStorage.
type StorageInterface = interface {
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	AcknowledgeAnomalyAlert(ctx context.Context, id uint) error
}

// NewAnomalyDetector creates a new AnomalyDetector with the ML pass disabled.
func NewAnomalyDetector(storage StorageInterface) *AnomalyDetector {
	return &AnomalyDetector{storage: storage}
}

// SetMLConfig enables (or reconfigures) the Isolation Forest pass. Defaults are
// applied per-pass, so passing a zero-valued config with Enabled=true uses the
// recommended parameters. With Enabled=false (the zero value) only the statistical
// rules run.
func (d *AnomalyDetector) SetMLConfig(cfg MLConfig) {
	d.ml = cfg
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
		// The baseline must reflect history STRICTLY BEFORE the detection window. The
		// 30-day query [now-30d, now] otherwise overlaps the [now-1h, now] window, so
		// every access about to be scored is already folded into knownUsers/knownIPs —
		// permanently disabling the new_user / new_ip rules (a first-time access learns
		// itself as "known"). Restrict the baseline to logs before the window start.
		priorLogs := make([]models.SecretAccessLog, 0, len(baselineLogs))
		for _, l := range baselineLogs {
			if l.AccessTime.Before(window) {
				priorLogs = append(priorLogs, l)
			}
		}
		baseline := buildBaseline(priorLogs, now)

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

		// Per-secret aggregate: a read-volume spike for the window versus the learned
		// baseline (one alert per secret per pass, not per access).
		if alert := volumeSpikeAlert(secret, len(recentLogs), baseline, now); alert != nil {
			_ = d.storage.CreateAnomalyAlert(ctx, alert)
		}

		// ML pass (opt-in): score this window's accesses against an Isolation Forest
		// trained on the secret's full 30-day baseline, catching multivariate outliers
		// the single-signal rules above miss.
		if d.ml.Enabled {
			for _, alert := range mlOutlierAlerts(secret, baselineLogs, recentLogs, d.ml, now) {
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

const (
	// volumeSpikeMinCount is the absolute floor below which a burst is never flagged —
	// avoids false positives on low-traffic secrets where a handful of reads dwarfs a
	// near-zero baseline.
	volumeSpikeMinCount = 10
	// volumeSpikeMultiplier flags a window whose read count exceeds this many times the
	// secret's learned hourly baseline.
	volumeSpikeMultiplier = 3.0
)

// isVolumeSpike reports whether recentCount reads in the (one-hour) detection window
// is anomalously high versus the secret's learned hourly baseline (dailyAvg / 24).
// Requires both an absolute floor and a multiple of the baseline, so neither a quiet
// secret seeing a few reads nor a busy secret at its normal rate is flagged.
func isVolumeSpike(recentCount int, baseline accessBaseline) bool {
	if recentCount < volumeSpikeMinCount {
		return false
	}
	hourlyAvg := baseline.dailyAvg / 24.0
	return float64(recentCount) > volumeSpikeMultiplier*hourlyAvg
}

// volumeSpikeAlert returns a frequency_spike alert when the window's read count is a
// spike versus the baseline, or nil otherwise. The alert is a per-secret aggregate, so
// it carries no single accessor/IP.
func volumeSpikeAlert(secret models.SecretNode, recentCount int, baseline accessBaseline, now time.Time) *models.AnomalyAlert {
	if !isVolumeSpike(recentCount, baseline) {
		return nil
	}
	return &models.AnomalyAlert{
		SecretNodeID: secret.ID,
		SecretName:   secret.Name,
		AlertType:    "frequency_spike",
		Severity:     "medium",
		Description: fmt.Sprintf("Unusual access volume: %d reads in the last hour (baseline ~%.1f/hour)",
			recentCount, baseline.dailyAvg/24.0),
		DetectedAt: now,
	}
}

// ListAlerts returns anomaly alerts. acknowledged filters by state: nil returns
// all, &true only acknowledged, &false only unacknowledged.
func (d *AnomalyDetector) ListAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	return d.storage.ListAnomalyAlerts(ctx, acknowledged)
}

// FilterAlerts narrows a set of alerts to those matching the given severity
// (low/medium/high) and/or alert type (off_hours/new_ip/new_user/frequency_spike).
// An empty string for either is "no constraint", so FilterAlerts(a, "", "") == a.
func FilterAlerts(alerts []models.AnomalyAlert, severity, alertType string) []models.AnomalyAlert {
	if severity == "" && alertType == "" {
		return alerts
	}
	out := make([]models.AnomalyAlert, 0, len(alerts))
	for _, a := range alerts {
		if severity != "" && a.Severity != severity {
			continue
		}
		if alertType != "" && a.AlertType != alertType {
			continue
		}
		out = append(out, a)
	}
	return out
}

// AcknowledgeAlert marks an alert as acknowledged.
func (d *AnomalyDetector) AcknowledgeAlert(ctx context.Context, id uint) error {
	return d.storage.AcknowledgeAnomalyAlert(ctx, id)
}
