// alert_escalation.go — automatic escalation of unacknowledged anomaly alerts
// (ISO 27001 A.5.5 / NIS2 detection & response). When an AnomalyAlert exceeds
// the EscalateAfterMinutes threshold without being acknowledged, it is dispatched
// to the NotificationChannels listed in the matching AlertEscalationPolicy.
package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// severityOrder maps severity label to a numeric rank for comparison.
// low < medium < high < critical.
var severityOrder = map[string]int{
	"low":      0,
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// severityAtLeast reports whether alertSeverity is at or above minSeverity.
func severityAtLeast(alertSeverity, minSeverity string) bool {
	aRank, aOK := severityOrder[alertSeverity]
	mRank, mOK := severityOrder[minSeverity]
	if !aOK || !mOK {
		return false
	}
	return aRank >= mRank
}

// EscalationResult summarises a single RunAlertEscalation pass.
type EscalationResult struct {
	Evaluated int // alerts checked
	Escalated int // alerts dispatched to at least one channel
	Skipped   int // already acknowledged or no matching policy
}

// RunAlertEscalation scans unacknowledged AnomalyAlerts, matches them against
// enabled AlertEscalationPolicies, and delivers to configured NotificationChannels.
// It is safe to call repeatedly (idempotent at the delivery layer; each call
// re-dispatches matching alerts — no "escalated" flag is set on the alert row).
func (c *KeyorixCore) RunAlertEscalation(ctx context.Context) (*EscalationResult, error) {
	policies, err := c.storage.ListAlertEscalationPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("alert escalation: list policies: %w", err)
	}

	// Only keep enabled policies with a positive delay.
	var active []models.AlertEscalationPolicy
	for _, p := range policies {
		if p.Enabled && p.EscalateAfterMinutes > 0 {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return &EscalationResult{}, nil
	}

	// Determine the earliest threshold: the minimum EscalateAfterMinutes across all
	// active policies. Any alert older than that threshold is a candidate for at least
	// one policy.
	minDelay := active[0].EscalateAfterMinutes
	for _, p := range active[1:] {
		if p.EscalateAfterMinutes < minDelay {
			minDelay = p.EscalateAfterMinutes
		}
	}

	threshold := c.now().Add(-time.Duration(minDelay) * time.Minute)
	alerts, err := c.storage.ListUnacknowledgedAnomalyAlertsBefore(ctx, threshold)
	if err != nil {
		return nil, fmt.Errorf("alert escalation: list alerts: %w", err)
	}

	result := &EscalationResult{Evaluated: len(alerts)}
	alertAge := func(a models.AnomalyAlert) time.Duration {
		return c.now().Sub(a.DetectedAt)
	}

	for _, alert := range alerts {
		age := alertAge(alert)
		dispatched := false
		for _, policy := range active {
			if age < time.Duration(policy.EscalateAfterMinutes)*time.Minute {
				continue
			}
			if !severityAtLeast(alert.Severity, policy.MinSeverity) {
				continue
			}
			// Dispatch to each channel in this policy.
			for _, cidStr := range splitChannelIDs(policy.ChannelIDs) {
				cid, err := strconv.ParseUint(cidStr, 10, 64)
				if err != nil {
					log.Printf("alert escalation: policy %d: invalid channel ID %q: %v", policy.ID, cidStr, err)
					continue
				}
				ch, err := c.storage.GetNotificationChannel(ctx, uint(cid))
				if err != nil {
					log.Printf("alert escalation: policy %d: channel %d: %v", policy.ID, cid, err)
					continue
				}
				if !ch.Enabled {
					continue
				}
				if derr := c.dispatchToChannel(ctx, ch, &alert, &policy); derr != nil {
					log.Printf("alert escalation: policy %d: channel %d: dispatch failed: %v", policy.ID, cid, derr)
				} else {
					dispatched = true
				}
			}
		}
		if dispatched {
			result.Escalated++
		} else {
			result.Skipped++
		}
	}
	// Alerts evaluated but with no matching policy also count as skipped.
	// (result.Evaluated already covers them; Skipped + Escalated should equal
	// the number of candidates returned by the store query.)
	return result, nil
}

// splitChannelIDs splits a comma-separated channel-ID string into trimmed, non-empty tokens.
func splitChannelIDs(ids string) []string {
	var out []string
	for _, s := range strings.Split(ids, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dispatchToChannel delivers an escalation notification to a single
// NotificationChannel. For webhook and slack types it performs an HTTP POST with
// a JSON payload; for other types (email, teams) it logs — full delivery
// integration for those types is left to the existing NotificationSink pipeline.
func (c *KeyorixCore) dispatchToChannel(ctx context.Context, ch *models.NotificationChannel, alert *models.AnomalyAlert, policy *models.AlertEscalationPolicy) error {
	switch ch.Type {
	case "webhook", "slack":
		return c.postJSONToURL(ctx, ch.URL, map[string]interface{}{
			"event":       "anomaly.escalated",
			"alert_id":    alert.ID,
			"severity":    alert.Severity,
			"alert_type":  alert.AlertType,
			"description": alert.Description,
			"secret_name": alert.SecretName,
			"accessed_by": alert.AccessedBy,
			"ip_address":  alert.IPAddress,
			"detected_at": alert.DetectedAt.Format(time.RFC3339),
			"policy_name": policy.Name,
			"channel":     ch.Name,
		})
	default:
		// email / teams: log and treat as delivered (best-effort for non-webhook types)
		log.Printf("alert escalation: channel %q (type=%s): escalation for alert %d logged (full delivery via notification sink)", ch.Name, ch.Type, alert.ID)
		return nil
	}
}

// postJSONToURL marshals payload to JSON and sends a best-effort HTTP POST to url.
func (c *KeyorixCore) postJSONToURL(_ context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body)) // #nosec G107 -- URL is operator-configured
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST %s: unexpected status %d", url, resp.StatusCode)
	}
	return nil
}

// --- CRUD for AlertEscalationPolicy ---

// CreateAlertEscalationPolicy validates and persists a new escalation policy.
func (c *KeyorixCore) CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) (*models.AlertEscalationPolicy, error) {
	if err := validateEscalationPolicy(p); err != nil {
		return nil, err
	}
	now := c.now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now
	if err := c.storage.CreateAlertEscalationPolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// GetAlertEscalationPolicy returns the policy with the given id.
func (c *KeyorixCore) GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error) {
	return c.storage.GetAlertEscalationPolicy(ctx, id)
}

// ListAlertEscalationPolicies returns all escalation policies.
func (c *KeyorixCore) ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error) {
	return c.storage.ListAlertEscalationPolicies(ctx)
}

// UpdateAlertEscalationPolicy applies field updates to the policy identified by id.
func (c *KeyorixCore) UpdateAlertEscalationPolicy(ctx context.Context, id uint, updates map[string]interface{}) (*models.AlertEscalationPolicy, error) {
	p, err := c.storage.GetAlertEscalationPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if v, ok := updates["name"].(string); ok && v != "" {
		p.Name = v
	}
	if v, ok := updates["min_severity"].(string); ok && v != "" {
		p.MinSeverity = v
	}
	if v, ok := updates["escalate_after_minutes"].(float64); ok {
		p.EscalateAfterMinutes = int(v)
	}
	if v, ok := updates["channel_ids"].(string); ok {
		p.ChannelIDs = v
	}
	if v, ok := updates["enabled"].(bool); ok {
		p.Enabled = v
	}
	if err := validateEscalationPolicy(p); err != nil {
		return nil, err
	}
	p.UpdatedAt = c.now().UTC()
	if err := c.storage.UpdateAlertEscalationPolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// DeleteAlertEscalationPolicy permanently removes the policy with the given id.
func (c *KeyorixCore) DeleteAlertEscalationPolicy(ctx context.Context, id uint) error {
	return c.storage.DeleteAlertEscalationPolicy(ctx, id)
}

// validateEscalationPolicy enforces invariants for create and update paths.
func validateEscalationPolicy(p *models.AlertEscalationPolicy) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("alert escalation policy name is required")
	}
	if _, ok := severityOrder[p.MinSeverity]; !ok {
		return fmt.Errorf("invalid min_severity %q: must be one of low, medium, high, critical", p.MinSeverity)
	}
	if p.EscalateAfterMinutes <= 0 {
		return fmt.Errorf("escalate_after_minutes must be a positive integer")
	}
	return nil
}
