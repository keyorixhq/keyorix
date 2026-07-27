package core

import (
	"context"
	"fmt"
	"log"
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
	// quarantine is how long an IP/user must have been observed before the live window
	// before buildBaseline trusts it as "known" (#101). Without this, an attacker's IP
	// ages into the baseline after just one lookback interval (as little as 1h) — the
	// very next pass sees it as historical and the new_ip/new_user rules go silent.
	// Requiring sustained presence for `quarantine` before promotion raises the cost of
	// that evasion from one pass to a sustained, repeatedly-observed presence.
	quarantine time.Duration
	// volumeMinCount overrides volumeSpikeMinCount when non-zero (ANOMALY-06).
	volumeMinCount int
	// cumulativeRateFloor is the dailyAvg ceiling below which the 24h cumulative rate
	// rule applies (ANOMALY-06). Defaults to defaultCumulativeRateFloor when zero.
	cumulativeRateFloor float64
	// cumulativeRateMax is the maximum accesses in a 24h window before the
	// cumulative_rate rule fires for low-traffic secrets (ANOMALY-06). Defaults to
	// defaultCumulativeRateMax when zero.
	cumulativeRateMax int
}

// minDetectionLookback is the floor for the per-pass scan window.
const minDetectionLookback = time.Hour

// defaultBaselineQuarantine is how long a newly observed IP/user must have been present
// before buildBaseline promotes it to "known" — see AnomalyDetector.quarantine.
const defaultBaselineQuarantine = 24 * time.Hour

const (
	// defaultCumulativeRateFloor is the dailyAvg threshold below which the 24h
	// cumulative rate rule applies. Secrets with a higher learnt rate already have
	// enough traffic for the per-hour spike rule to work reliably.
	defaultCumulativeRateFloor = 1.0
	// defaultCumulativeRateMax is the absolute access count over a 24h rolling
	// window that triggers a cumulative_rate alert for low-traffic secrets. An
	// attacker reading 9 times/hour evades the per-hour floor (10) indefinitely,
	// but crosses this 24h cumulative threshold in just over two hours.
	defaultCumulativeRateMax = 20
)

// StorageInterface is satisfied by *storage.LocalStorage and *storage.RemoteStorage.
type StorageInterface = interface {
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	// PrincipalSecretFirstSeen backs the per-principal breadth-exfiltration pass
	// (#101): see internal/core/storage.Storage's doc comment for the full rationale.
	PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	// LogAuditEvent backs auditBusinessHoursConfig (#144) — a business-hours config
	// change must be on the audit record even though it's applied in-memory here.
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
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

// SetBaselineQuarantine overrides how long an IP/user must be observed before the live
// window before it is trusted as "known" baseline (see AnomalyDetector.quarantine). A
// non-positive value disables quarantine (only the live window itself is excluded,
// the pre-#101 behaviour) — accepted as an explicit opt-out, not silently floored.
func (d *AnomalyDetector) SetBaselineQuarantine(window time.Duration) {
	d.quarantine = window
}

// SetVolumeMinCount overrides the absolute floor below which the per-hour volume spike
// detector never fires (ANOMALY-06). Positive values only; non-positive is ignored.
func (d *AnomalyDetector) SetVolumeMinCount(n int) {
	if n > 0 {
		d.volumeMinCount = n
	}
}

// SetCumulativeRateFloor sets the dailyAvg threshold below which the 24h cumulative
// rate rule applies (ANOMALY-06). Positive values only; non-positive is ignored.
func (d *AnomalyDetector) SetCumulativeRateFloor(floor float64) {
	if floor > 0 {
		d.cumulativeRateFloor = floor
	}
}

// SetCumulativeRateMax sets the maximum accesses in a 24h rolling window before the
// cumulative_rate rule fires for low-traffic secrets (ANOMALY-06). Positive values
// only; non-positive is ignored.
func (d *AnomalyDetector) SetCumulativeRateMax(max int) {
	if max > 0 {
		d.cumulativeRateMax = max
	}
}

// NewAnomalyDetector creates a new AnomalyDetector with the ML pass disabled, the
// off-hours window at its UTC 22:00–06:00 default, and the baseline quarantine at its
// 24h default.
func NewAnomalyDetector(storage StorageInterface) *AnomalyDetector {
	return &AnomalyDetector{
		storage:    storage,
		offHours:   defaultOffHoursPolicy(),
		lookback:   minDetectionLookback,
		quarantine: defaultBaselineQuarantine,
	}
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

// EventAnomalyBusinessHoursConfigured audits a change to the off_hours rule's
// timezone/band (#144). A degenerate (start == end) or otherwise narrowed band
// silently blinds that rule with no other visible symptom, so the config CHANGE
// itself — not just its effect — must be on the record.
const EventAnomalyBusinessHoursConfigured = "anomaly.business_hours_configured" // #nosec G101 -- audit event type, not a credential

// SetBusinessHours configures the off_hours rule's timezone and band. tz is an IANA
// name ("" = UTC); the off-hours band is [startHour, endHour) wrapping midnight, in
// that timezone. A blank tz keeps UTC, and the band defaults to 22:00–06:00 unless
// overridden. Because 0 is the config zero value AND a valid hour, both hours being 0
// is treated as "unset" (a 0–0 band would be empty) — set the timezone alone and the
// default band is kept. Returns an error for an unparseable timezone OR a degenerate
// band (startHour == endHour for any other, explicitly-supplied pair) — a start==end
// band matches no hour in isOffHours, which would silently disable the rule with no
// validation error and no audit trail if allowed through. Either error leaves the
// prior policy unchanged. On success the new band is recorded as an audit event.
func (d *AnomalyDetector) SetBusinessHours(ctx context.Context, tz string, startHour, endHour int) error {
	p := defaultOffHoursPolicy()
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return fmt.Errorf("anomaly business_hours timezone %q: %w", tz, err)
		}
		p.loc = loc
	}
	if startHour != 0 || endHour != 0 { // both zero = unset → keep the default band
		if validHour(startHour) && validHour(endHour) && startHour == endHour {
			return fmt.Errorf("anomaly business_hours: start_hour and end_hour must differ (an equal start/end band is empty and would silently disable the off_hours rule; pass 0,0 to explicitly keep the default band)")
		}
		if validHour(startHour) {
			p.start = startHour
		}
		if validHour(endHour) {
			p.end = endHour
		}
	}
	d.offHours = p
	d.auditBusinessHoursConfig(ctx, tz, p)
	return nil
}

// auditBusinessHoursConfig records the newly-applied off-hours band/timezone as an
// audit event. Best-effort: a storage failure here must not undo the in-memory
// policy change SetBusinessHours already applied, but it is logged loudly (a missed
// audit write for a detection-control config change is itself a small gap).
func (d *AnomalyDetector) auditBusinessHoursConfig(ctx context.Context, tz string, p offHoursPolicy) {
	if d.storage == nil {
		return
	}
	tzLabel := tz
	if tzLabel == "" {
		tzLabel = "UTC"
	}
	ok := true
	event := &models.AuditEvent{
		EventType: EventAnomalyBusinessHoursConfigured,
		Description: fmt.Sprintf("anomaly off-hours band configured: timezone=%s band=%02d:00-%02d:00",
			tzLabel, p.start, p.end),
		Success:   &ok,
		ActorType: "system",
		EventTime: time.Now(),
	}
	if err := d.storage.LogAuditEvent(ctx, event); err != nil {
		log.Printf("SECURITY: anomaly business-hours config: failed to write audit event: %v", err)
	}
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
		failures += d.detectOneSecretAnomalies(ctx, secret, baselineWindow, window, now)
	}

	// Per-principal aggregate (#101): a principal reading many DIFFERENT secrets it has
	// never touched before is invisible to every rule above — each is scoped to a single
	// secret's own baseline, so the same breadth-exfiltrating principal looks merely
	// "new" to N separate secrets rather than triggering one aggregate signal. Runs once
	// per pass across all secrets, not per secret.
	breadthAlerts, err := detectPrincipalBreadth(ctx, d.storage, now, window, baselineWindow)
	if err != nil {
		failures++
	}
	failures += d.saveAlerts(ctx, breadthAlerts)

	if failures > 0 {
		return fmt.Errorf("anomaly detection completed with %d storage failure(s) — some alerts may not have been recorded", failures)
	}
	return nil
}

// detectOneSecretAnomalies runs all anomaly rules for a single secret and returns the
// number of storage failures encountered while saving alerts.
func (d *AnomalyDetector) detectOneSecretAnomalies(ctx context.Context, secret models.SecretNode, baselineWindow, window, now time.Time) int {
	// Build 30-day baseline. A secret with NO baseline history (brand new, or unread
	// in 30 days) is NOT skipped — detectAnomalies still flags off-hours access and
	// first-ever new_ip/new_user (severity is scaled down for that case). Skipping was
	// the prior blind spot an attacker targeting a freshly-provisioned secret could exploit.
	baselineLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, baselineWindow)
	if err != nil {
		// #365: log which secret so an operator can distinguish a transient DB hiccup
		// from a genuine coverage gap (the detection window is only ~1h and is never
		// retroactively re-evaluated).
		log.Printf("anomaly detection: baseline access-log read for secret %d: %v — skipping detection for this secret this pass", secret.ID, err)
		return 1
	}
	baseline := buildBaseline(baselineLogs, now, window, d.quarantine)
	recentLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, window)
	if err != nil {
		log.Printf("anomaly detection: detection-window access-log read for secret %d: %v — skipping detection for this secret this pass", secret.ID, err)
		return 1
	}
	failures := 0
	for _, accessLog := range recentLogs {
		failures += d.saveAlerts(ctx, detectAnomalies(secret, accessLog, baseline, d.offHours))
	}
	// Per-secret aggregate: a read-volume spike for the window vs. the learned baseline
	// (one alert per secret per pass, not per access).
	if alert := volumeSpikeAlert(secret, len(recentLogs), baseline, d.effectiveVolumeMinCount(), now); alert != nil {
		if err := d.storage.CreateAnomalyAlert(ctx, alert); err != nil {
			failures++
		}
	}
	// ANOMALY-06 cumulative rate rule: count accesses over the last 24h from
	// baselineLogs (which covers 30 days) so we catch sustained low-rate exfiltration
	// that stays below the per-hour floor on every individual pass.
	window24h := now.Add(-24 * time.Hour)
	logs24h := logsSince(baselineLogs, window24h)
	// Also include any logs in the current detection window (recentLogs) that fall
	// within the last 24h — the baseline query may exclude the live window on some
	// storage implementations.
	for _, lg := range recentLogs {
		if !lg.AccessTime.Before(window24h) {
			logs24h = append(logs24h, lg)
		}
	}
	if alert := cumulativeRateAlert(secret, len(logs24h), baseline, d.effectiveCumulativeRateFloor(), d.effectiveCumulativeRateMax(), now); alert != nil {
		if err := d.storage.CreateAnomalyAlert(ctx, alert); err != nil {
			failures++
		}
	}
	// ML pass (opt-in): score this window's accesses against an Isolation Forest trained
	// on prior history, catching multivariate outliers the single-signal rules miss.
	// Train only on logs BEFORE the window — otherwise the forest learns this window's
	// reads as normal and can't isolate the very accesses it is scoring.
	if d.ml.Enabled {
		failures += d.saveAlerts(ctx, mlOutlierAlerts(secret, logsBefore(baselineLogs, window), recentLogs, d.ml, now))
	}
	return failures
}

// saveAlerts persists a slice of anomaly alerts, returning the number of storage
// failures. Each alert is saved independently so one failure doesn't drop the rest.
func (d *AnomalyDetector) saveAlerts(ctx context.Context, alerts []models.AnomalyAlert) int {
	failures := 0
	for _, alert := range alerts {
		if err := d.storage.CreateAnomalyAlert(ctx, &alert); err != nil {
			failures++
		}
	}
	return failures
}

const (
	// principalBreadthMinNewSecrets is the minimum count of distinct secrets a
	// principal must access in the live window — NONE of which it touched during the
	// 30-day baseline — before a principal_breadth alert fires. Catches breadth
	// exfiltration (many different secrets each read once) that the per-secret rules
	// structurally cannot see.
	principalBreadthMinNewSecrets = 5
	// principalBreadthHighMultiplier: at or above principalBreadthMinNewSecrets times
	// this multiplier, the alert is "high" severity rather than "medium".
	principalBreadthHighMultiplier = 2
)

// detectPrincipalBreadth aggregates access logs by principal (not by secret) over the
// 30-day baseline and flags a principal whose EARLIEST-ever access to an unusually high
// number of secrets falls inside the live scan window — the per-secret rules never see
// this, since each secret only observes "one access from a possibly-new actor." The
// live-window boundary is applied here in Go against a real time.Time, not pushed into
// the storage query's SQL bound — see PrincipalSecretFirstSeen's doc comment for why.
func detectPrincipalBreadth(ctx context.Context, s StorageInterface, now, windowStart, baselineWindow time.Time) ([]models.AnomalyAlert, error) {
	firstSeen, err := s.PrincipalSecretFirstSeen(ctx, baselineWindow)
	if err != nil {
		return nil, err
	}

	var alerts []models.AnomalyAlert
	for principal, secrets := range firstSeen {
		newCount := 0
		for _, t := range secrets {
			if !t.Before(windowStart) { // first ever access to this secret falls in the live window
				newCount++
			}
		}
		if newCount < principalBreadthMinNewSecrets {
			continue
		}
		severity := "medium"
		if newCount >= principalBreadthMinNewSecrets*principalBreadthHighMultiplier {
			severity = "high"
		}
		alerts = append(alerts, models.AnomalyAlert{
			AlertType: "principal_breadth",
			Severity:  severity,
			Description: fmt.Sprintf(
				"%s accessed %d distinct secrets with no prior access history in the last scan window — possible breadth exfiltration",
				principal, newCount),
			AccessedBy: principal,
			DetectedAt: now,
		})
	}
	return alerts, nil
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

// logsSince returns the access logs whose AccessTime is at or after t, preserving
// order. Used to compute a 24h rolling count from the already-fetched baseline slice
// without an extra storage query.
func logsSince(logs []models.SecretAccessLog, t time.Time) []models.SecretAccessLog {
	out := make([]models.SecretAccessLog, 0, len(logs))
	for _, lg := range logs {
		if !lg.AccessTime.Before(t) {
			out = append(out, lg)
		}
	}
	return out
}

// baselineMinSeen is the minimum number of times an IP or user must appear in the
// pre-quarantine baseline window before it is promoted to "known." A single occurrence
// is not sufficient — an attacker can generate exactly one historical access and then
// be treated as trusted on every subsequent pass. Requiring N distinct baseline
// observations raises the cost of that poisoning attack from one access to a sustained,
// repeatedly-observed presence spanning the full quarantine period.
const baselineMinSeen = 3

// buildBaseline computes the statistical baseline from historical access logs,
// EXCLUDING the live detection window [windowStart, now]. The reads being evaluated
// this pass must not seed their own baseline: the baseline query spans 30 days and
// therefore contains the last hour too, so without this exclusion a genuinely new IP
// or user would already appear in knownIPs/knownUsers and the new_ip / new_user rules
// could never fire. Excluding the window also keeps the volume baseline (dailyAvg)
// from inflating itself with the very burst a spike check is meant to catch.
//
// quarantine additionally withholds knownIPs/knownUsers promotion for accesses that,
// while before the live window, are still more recent than `quarantine` (#101): without
// this, an IP/user first observed in pass N is already "known" by pass N+1 — as little
// as one lookback interval later — so an attacker's IP self-poisons the baseline and
// stops triggering new_ip/new_user after a single successful access. Requiring an
// access to predate `windowStart - quarantine`, not just `windowStart`, means an IP/user
// must be observed continuously for the full quarantine period before it is trusted.
//
// ANOMALY-02: a single pre-quarantine access is no longer sufficient to promote an
// IP/user to "known" — it must appear at least baselineMinSeen times. This prevents an
// attacker from generating one carefully-timed historical access to permanently silence
// the new_ip/new_user rules.
//
// dailyAvg counts only accesses that are OUTSIDE the quarantine window (older than
// trustCutoff) to prevent warm-up accesses during quarantine from inflating the volume
// baseline, which would in turn raise the spike threshold and blind the spike detector.
func buildBaseline(logs []models.SecretAccessLog, now, windowStart time.Time, quarantine time.Duration) accessBaseline {
	b := accessBaseline{
		knownIPs:   make(map[string]bool),
		knownUsers: make(map[string]bool),
	}
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)
	trustCutoff := windowStart.Add(-quarantine)

	// Count occurrences for each IP/user in the pre-quarantine window so we can
	// apply the baselineMinSeen threshold before promoting to "known."
	ipCount := make(map[string]int)
	userCount := make(map[string]int)
	// recentCount tracks daily volume for dailyAvg, counting only accesses that are
	// outside the quarantine window to avoid inflating the spike baseline.
	recentCount := 0

	for _, log := range logs {
		// Skip the live window so this pass's reads don't establish their own baseline.
		if !log.AccessTime.Before(windowStart) {
			continue
		}
		if !log.AccessTime.Before(trustCutoff) {
			// Inside the quarantine window: count toward the frequency maps for threshold
			// checking but do NOT yet promote to "known" — that happens after the loop once
			// we know the full count.
			continue
		}
		// Pre-quarantine access: count it for trust promotion and for dailyAvg.
		if log.IPAddress != "" {
			ipCount[log.IPAddress]++
		}
		if log.AccessedBy != "" {
			userCount[log.AccessedBy]++
		}
		if log.AccessTime.After(sevenDaysAgo) {
			recentCount++
		}
	}

	// Promote IPs/users that meet the minimum-seen threshold.
	for ip, cnt := range ipCount {
		if cnt >= baselineMinSeen {
			b.knownIPs[ip] = true
		}
	}
	for user, cnt := range userCount {
		if cnt >= baselineMinSeen {
			b.knownUsers[user] = true
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

	// Rule 2: Access from unknown IP. An empty baseline (no prior history at all —
	// bootstrap, or a brand-new secret) used to suppress this rule entirely (#101): a
	// first-ever access from ANY IP was silently waved through with zero novelty
	// signal, which is exactly what an attacker deliberately targeting a
	// freshly-provisioned, never-accessed secret would rely on. It still fires, but at
	// "low" severity when there is no established baseline to violate — an established
	// pattern being violated (baseline non-empty) is a stronger signal than a secret's
	// first-ever access being from some IP, which is unremarkable on its own but now at
	// least visible and auditable rather than invisible.
	if log.IPAddress != "" && !baseline.knownIPs[log.IPAddress] {
		severity := "high"
		desc := fmt.Sprintf("Secret accessed from unrecognised IP address: %s", log.IPAddress)
		if len(baseline.knownIPs) == 0 {
			severity = "low"
			desc = fmt.Sprintf("Secret's first observed access is from IP address %s (no prior baseline to compare against)", log.IPAddress)
		}
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "new_ip",
			Severity:     severity,
			Description:  desc,
			AccessedBy:   log.AccessedBy,
			IPAddress:    log.IPAddress,
			DetectedAt:   now,
		})
	}

	// Rule 3: Access by unknown user — same empty-baseline reasoning as Rule 2.
	if log.AccessedBy != "" && !baseline.knownUsers[log.AccessedBy] {
		severity := "high"
		desc := fmt.Sprintf("Secret accessed by user with no prior access history: %s", log.AccessedBy)
		if len(baseline.knownUsers) == 0 {
			severity = "low"
			desc = fmt.Sprintf("Secret's first observed access is by user %s (no prior baseline to compare against)", log.AccessedBy)
		}
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "new_user",
			Severity:     severity,
			Description:  desc,
			AccessedBy:   log.AccessedBy,
			IPAddress:    log.IPAddress,
			DetectedAt:   now,
		})
	}

	return alerts
}

const (
	// volumeSpikeMinCount is the default absolute floor below which a burst is never
	// flagged — avoids false positives on low-traffic secrets where a handful of reads
	// dwarfs a near-zero baseline. Overridable per-deployment via AnomalyConfigRecord.
	volumeSpikeMinCount = 10
	// volumeSpikeMultiplier flags a window whose read count exceeds this many times the
	// secret's learned hourly baseline.
	volumeSpikeMultiplier = 3.0
)

// effectiveVolumeMinCount returns the configurable floor, falling back to the default.
func (d *AnomalyDetector) effectiveVolumeMinCount() int {
	if d.volumeMinCount > 0 {
		return d.volumeMinCount
	}
	return volumeSpikeMinCount
}

// effectiveCumulativeRateFloor returns the configured floor, falling back to the default.
func (d *AnomalyDetector) effectiveCumulativeRateFloor() float64 {
	if d.cumulativeRateFloor > 0 {
		return d.cumulativeRateFloor
	}
	return defaultCumulativeRateFloor
}

// effectiveCumulativeRateMax returns the configured max, falling back to the default.
func (d *AnomalyDetector) effectiveCumulativeRateMax() int {
	if d.cumulativeRateMax > 0 {
		return d.cumulativeRateMax
	}
	return defaultCumulativeRateMax
}

// isVolumeSpike reports whether recentCount reads in the (one-hour) detection window
// is anomalously high versus the secret's learned hourly baseline (dailyAvg / 24).
// Requires both an absolute floor and a multiple of the baseline, so neither a quiet
// secret seeing a few reads nor a busy secret at its normal rate is flagged.
// minCount is the absolute floor (configurable via AnomalyDetector.volumeMinCount).
func isVolumeSpike(recentCount int, baseline accessBaseline, minCount int) bool {
	if recentCount < minCount {
		return false
	}
	hourlyAvg := baseline.dailyAvg / 24.0
	return float64(recentCount) > volumeSpikeMultiplier*hourlyAvg
}

// isCumulativeRateAnomaly reports whether the 24h rolling access count is anomalously
// high for a secret whose learned daily average is below the configured floor. This
// catches the sustained low-rate exfiltration pattern (e.g. 9 reads/hour) that the
// per-hour spike floor misses: 9 reads/hour stays below volumeSpikeMinCount=10 per
// pass, but accumulates to 216 reads in 24h — well above the cumulative threshold.
//
// The rule only applies when dailyAvg < rateFloor so it doesn't interfere with
// high-traffic secrets that already have enough history for the per-hour spike rule.
func isCumulativeRateAnomaly(count24h int, dailyAvg float64, rateFloor float64, rateMax int) bool {
	if dailyAvg >= rateFloor {
		return false // high-traffic secret: per-hour spike rule already covers it
	}
	return count24h > rateMax
}

// volumeSpikeAlert returns a frequency_spike alert when the window's read count is a
// spike versus the baseline, or nil otherwise. The alert is a per-secret aggregate, so
// it carries no single accessor/IP.
func volumeSpikeAlert(secret models.SecretNode, recentCount int, baseline accessBaseline, minCount int, now time.Time) *models.AnomalyAlert {
	if !isVolumeSpike(recentCount, baseline, minCount) {
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

// cumulativeRateAlert returns a cumulative_rate alert when the 24h access count is
// anomalously high for a low-traffic secret, or nil otherwise.
func cumulativeRateAlert(secret models.SecretNode, count24h int, baseline accessBaseline, rateFloor float64, rateMax int, now time.Time) *models.AnomalyAlert {
	if !isCumulativeRateAnomaly(count24h, baseline.dailyAvg, rateFloor, rateMax) {
		return nil
	}
	return &models.AnomalyAlert{
		SecretNodeID: secret.ID,
		SecretName:   secret.Name,
		AlertType:    "cumulative_rate",
		Severity:     "medium",
		Description: fmt.Sprintf("Sustained access volume: %d reads in the last 24h for a low-traffic secret (baseline ~%.1f/day); possible slow-rate exfiltration",
			count24h, baseline.dailyAvg),
		DetectedAt: now,
	}
}

// ListAlerts returns anomaly alerts. acknowledged filters by state: nil returns
// all, &true only acknowledged, &false only unacknowledged.
func (d *AnomalyDetector) ListAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	return d.storage.ListAnomalyAlerts(ctx, acknowledged)
}

// FilterAlerts narrows a set of alerts to those matching the given severity
// (low/medium/high) and/or alert type (off_hours/new_ip/new_user/frequency_spike/
// ml_outlier/principal_breadth).
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
