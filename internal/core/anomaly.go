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
	storage  StorageInterface
	ml       MLConfig       // ML pass; disabled by default (see SetMLConfig)
	offHours offHoursPolicy // off_hours rule window; defaults to UTC 22:00–06:00
	// lookback is how far back each pass scans. It must be >= the scheduler interval, or
	// the access logs between (now-lookback) and the prior run go unexamined by any rule
	// — a coverage blind spot when the operator sets a scan cadence longer than the
	// default. Defaults to 1h; SetLookback raises it to match the configured interval.
	lookback time.Duration
}

// minDetectionLookback is the floor for the per-pass scan window.
const minDetectionLookback = time.Hour

// StorageInterface is satisfied by *storage.LocalStorage and *storage.RemoteStorage.
type StorageInterface = interface {
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	AcknowledgeAnomalyAlert(ctx context.Context, id uint) error
}

// SetLookback sets how far back each detection pass scans, flooring it at one hour. The
// scheduler should set this to its scan interval so consecutive passes cover a
// contiguous timeline (a longer cadence must scan a proportionally longer window, else
// the gap between passes is never analysed).
func (d *AnomalyDetector) SetLookback(window time.Duration) {
	if window < minDetectionLookback {
		window = minDetectionLookback
	}
	d.lookback = window
}

// NewAnomalyDetector creates a new AnomalyDetector with the ML pass disabled and the
// off-hours window at its UTC 22:00–06:00 default.
func NewAnomalyDetector(storage StorageInterface) *AnomalyDetector {
	return &AnomalyDetector{storage: storage, offHours: defaultOffHoursPolicy(), lookback: minDetectionLookback}
}

// SetMLConfig enables (or reconfigures) the Isolation Forest pass. Defaults are
// applied per-pass, so passing a zero-valued config with Enabled=true uses the
// recommended parameters. With Enabled=false (the zero value) only the statistical
// rules run.
func (d *AnomalyDetector) SetMLConfig(cfg MLConfig) {
	d.ml = cfg
}

// offHoursPolicy defines the "off hours" band for the off_hours rule. Hours are
// evaluated in loc, and the band is [start, end) wrapping midnight (e.g. 22→6 means
// 22:00–23:59 plus 00:00–05:59).
type offHoursPolicy struct {
	loc   *time.Location
	start int // off-hours band start hour [0,23]
	end   int // off-hours band end hour [0,23], exclusive
}

// defaultOffHoursPolicy is the legacy hardcoded behaviour: UTC, 22:00–06:00.
func defaultOffHoursPolicy() offHoursPolicy {
	return offHoursPolicy{loc: time.UTC, start: 22, end: 6}
}

// isOffHours reports whether t falls in the off-hours band, evaluated in the policy's
// timezone. A band with start <= end is a normal interval [start, end); start > end is
// a band that wraps midnight.
func (p offHoursPolicy) isOffHours(t time.Time) bool {
	loc := p.loc
	if loc == nil { // zero-value policy → treat as UTC rather than panic in t.In
		loc = time.UTC
	}
	h := t.In(loc).Hour()
	if p.start <= p.end {
		return h >= p.start && h < p.end
	}
	return h >= p.start || h < p.end
}

// validHour reports whether h is a valid clock hour [0,23].
func validHour(h int) bool { return h >= 0 && h <= 23 }

// SetBusinessHours configures the off_hours rule's timezone and band. tz is an IANA
// name ("" = UTC); the off-hours band is [startHour, endHour) wrapping midnight, in
// that timezone. A blank tz keeps UTC, and the band defaults to 22:00–06:00 unless
// overridden. Because 0 is the config zero value AND a valid hour, both hours being 0
// is treated as "unset" (a 0–0 band would be empty) — set the timezone alone and the
// default band is kept. Returns an error only for an unparseable timezone, leaving the
// prior policy unchanged.
func (d *AnomalyDetector) SetBusinessHours(tz string, startHour, endHour int) error {
	p := defaultOffHoursPolicy()
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return fmt.Errorf("anomaly business_hours timezone %q: %w", tz, err)
		}
		p.loc = loc
	}
	if startHour != 0 || endHour != 0 { // both zero = unset → keep the default band
		if validHour(startHour) {
			p.start = startHour
		}
		if validHour(endHour) {
			p.end = endHour
		}
	}
	d.offHours = p
	return nil
}

// accessBaseline holds statistical baseline for a secret's access patterns.
type accessBaseline struct {
	knownIPs   map[string]bool
	knownUsers map[string]bool
	dailyAvg   float64 // average accesses per day over last 7 days
}

// RunDetection analyses SecretAccessLog over the configured lookback window and emits
// AnomalyAlert rows. Safe to call on a schedule — idempotent per detection window (the
// dedup window absorbs the overlap between passes). It is best-effort per secret but
// returns a non-nil error if any storage operation failed, so the scheduler outcome
// reflects a partial failure rather than silently reporting success.
func (d *AnomalyDetector) RunDetection(ctx context.Context, secrets []models.SecretNode) error {
	now := time.Now().UTC()
	lookback := d.lookback
	if lookback < minDetectionLookback {
		lookback = minDetectionLookback
	}
	window := now.Add(-lookback)
	baselineWindow := now.Add(-30 * 24 * time.Hour)

	var failures int
	for _, secret := range secrets {
		// Build 30-day baseline
		baselineLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, baselineWindow)
		if err != nil {
			failures++
			continue
		}
		if len(baselineLogs) == 0 {
			continue
		}
		baseline := buildBaseline(baselineLogs, now, window)

		// Get recent accesses over the lookback window.
		recentLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, window)
		if err != nil {
			failures++
			continue
		}

		for _, accessLog := range recentLogs {
			alerts := detectAnomalies(secret, accessLog, baseline, d.offHours)
			for _, alert := range alerts {
				if err := d.storage.CreateAnomalyAlert(ctx, &alert); err != nil {
					failures++
				}
			}
		}

		// Per-secret aggregate: a read-volume spike for the window versus the learned
		// baseline (one alert per secret per pass, not per access).
		if alert := volumeSpikeAlert(secret, len(recentLogs), baseline, now); alert != nil {
			if err := d.storage.CreateAnomalyAlert(ctx, alert); err != nil {
				failures++
			}
		}

		// ML pass (opt-in): score this window's accesses against an Isolation Forest
		// trained on the secret's prior history, catching multivariate outliers the
		// single-signal rules above miss. Train only on logs BEFORE the window — for the
		// same reason buildBaseline excludes it: otherwise the forest learns this window's
		// reads as normal (and the IP/user frequency features count the burst as
		// established), so it can't isolate the very accesses it is scoring.
		if d.ml.Enabled {
			trainLogs := logsBefore(baselineLogs, window)
			for _, alert := range mlOutlierAlerts(secret, trainLogs, recentLogs, d.ml, now) {
				if err := d.storage.CreateAnomalyAlert(ctx, &alert); err != nil {
					failures++
				}
			}
		}
	}
	if failures > 0 {
		return fmt.Errorf("anomaly detection completed with %d storage failure(s) — some alerts may not have been recorded", failures)
	}
	return nil
}

// logsBefore returns the access logs that occurred strictly before t, preserving
// order. Used to exclude the live detection window from the ML training set so this
// pass's reads don't train the model that is meant to flag them.
func logsBefore(logs []models.SecretAccessLog, t time.Time) []models.SecretAccessLog {
	out := make([]models.SecretAccessLog, 0, len(logs))
	for _, lg := range logs {
		if lg.AccessTime.Before(t) {
			out = append(out, lg)
		}
	}
	return out
}

// buildBaseline computes the statistical baseline from historical access logs,
// EXCLUDING the live detection window [windowStart, now]. The reads being evaluated
// this pass must not seed their own baseline: the baseline query spans 30 days and
// therefore contains the last hour too, so without this exclusion a genuinely new IP
// or user would already appear in knownIPs/knownUsers and the new_ip / new_user rules
// could never fire. Excluding the window also keeps the volume baseline (dailyAvg)
// from inflating itself with the very burst a spike check is meant to catch.
func buildBaseline(logs []models.SecretAccessLog, now, windowStart time.Time) accessBaseline {
	b := accessBaseline{
		knownIPs:   make(map[string]bool),
		knownUsers: make(map[string]bool),
	}
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)
	recentCount := 0

	for _, log := range logs {
		// Skip the live window so this pass's reads don't establish their own baseline.
		if !log.AccessTime.Before(windowStart) {
			continue
		}
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
func detectAnomalies(secret models.SecretNode, log models.SecretAccessLog, baseline accessBaseline, offHours offHoursPolicy) []models.AnomalyAlert {
	var alerts []models.AnomalyAlert
	now := time.Now().UTC()

	// Rule 1: Off-hours access (configurable band + timezone; default 22:00–06:00 UTC).
	if offHours.isOffHours(log.AccessTime) {
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "off_hours",
			Severity:     "medium",
			Description:  fmt.Sprintf("Secret accessed outside business hours at %s", log.AccessTime.In(offHours.loc).Format("15:04 MST")),
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
