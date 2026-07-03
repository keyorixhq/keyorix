// anomaly_alerting.go — proactive alerting for detected anomalies (NIS2 detection
// & response). Detection (anomaly.go) persists AnomalyAlert rows; this pushes the
// not-yet-alerted ones out — to the project's admins (in-app notification) and to
// the audit trail (event security.anomaly_detected, which the SIEM forwarder picks
// up) — and marks them alerted so each anomaly is announced once. Run by the
// anomaly scheduler after each detection pass when anomaly_alerts is enabled.
package core

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventAnomalyDetected is the audit event type emitted for each anomaly pushed out;
// it flows through the SIEM forwarder like any audit event.
const EventAnomalyDetected = "security.anomaly_detected" // #nosec G101 -- audit event type, not a credential

// EventAnomalyAcknowledged audits an operator dismissing an anomaly alert — a mutation
// of a security-detection record, so WHO dismissed WHICH alert must land on the
// append-only trail (otherwise an attacker could quietly bury an alert about their own
// activity).
const EventAnomalyAcknowledged = "security.anomaly_acknowledged" // #nosec G101 -- audit event type, not a credential

// AcknowledgeAnomalyAlert marks an anomaly alert acknowledged and records who did it on
// the audit trail. actorID is the operator performing the dismissal. The acknowledge is
// gated at the transport by a write-level permission (it mutates a detection record).
func (c *KeyorixCore) AcknowledgeAnomalyAlert(ctx context.Context, actorID, alertID uint) error {
	if err := c.storage.AcknowledgeAnomalyAlert(ctx, alertID, actorID, c.now()); err != nil {
		return err
	}
	var aid *uint
	if actorID != 0 {
		a := actorID
		aid = &a
	}
	c.writeAuditEventFull(ctx, EventAnomalyAcknowledged, aid, nil, nil, "",
		fmt.Sprintf("anomaly alert %d acknowledged (dismissed) by user %d", alertID, actorID))
	return nil
}

// AlertNewAnomalies pushes every not-yet-alerted anomaly to the project's admins
// and the audit/SIEM pipeline, marking each alerted. Returns the number announced.
// Idempotent: an already-alerted anomaly is skipped.
func (c *KeyorixCore) AlertNewAnomalies(ctx context.Context) (int, error) {
	alerts, err := c.storage.ListUnalertedAnomalyAlerts(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list unalerted anomalies: %w", err)
	}
	announced := 0
	for i := range alerts {
		a := &alerts[i]

		// Resolve the owning project (for scoping the audit event + admin notify).
		var projectID uint
		if a.SecretNodeID != 0 {
			if s, err := c.storage.GetSecret(ctx, a.SecretNodeID); err == nil && s != nil {
				projectID = s.ProjectID
			}
		}

		// Audit + SIEM: a security event for the SOC, regardless of project.
		var sid, pid *uint
		if a.SecretNodeID != 0 {
			s := a.SecretNodeID
			sid = &s
		}
		if projectID != 0 {
			p := projectID
			pid = &p
		}
		c.writeAuditEventFull(ctx, EventAnomalyDetected, nil, sid, pid, a.IPAddress,
			fmt.Sprintf("anomaly (%s, %s): %s", a.AlertType, a.Severity, a.Description))

		// In-app: alert the project's approver-role members. The audit/SIEM event
		// above is already durable regardless, so this is a detection-latency gap
		// on failure, not a control failure — surface it loudly rather than
		// swallowing it (#166, same silent-fail-on-ListProjectMembers-error pattern
		// as notifyBreakGlassAdmins).
		if nerr := c.notifyAnomalyAdmins(ctx, projectID, a); nerr != nil {
			log.Printf("SECURITY: anomaly alert %d (project %d): admin notification failed: %v", a.ID, projectID, nerr)
		}

		if err := c.storage.MarkAnomalyAlertAlerted(ctx, a.ID); err != nil {
			// Couldn't mark alerted — skip counting so a retry re-announces rather
			// than silently dropping (the audit event is already out, harmless dup).
			continue
		}
		announced++
	}
	return announced, nil
}

// notifyAnomalyAdmins sends an in-app alert to the project's approver-role members.
// With no resolvable project the in-app notify is skipped (the audit + SIEM event
// still carries it) — not an error. Individual notify() delivery stays best-effort,
// but a failure to list the project's members is a distinct, louder failure mode
// (no admin was even considered), so that's returned as an error (#166).
func (c *KeyorixCore) notifyAnomalyAdmins(ctx context.Context, projectID uint, a *models.AnomalyAlert) error {
	if projectID == 0 {
		return nil
	}
	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		return fmt.Errorf("list project %d members: %w", projectID, err)
	}
	pid := projectID
	title := fmt.Sprintf("Anomaly detected (%s)", a.Severity)
	msg := fmt.Sprintf("%s on secret %q by %s from %s — %s", a.AlertType, a.SecretName, a.AccessedBy, a.IPAddress, a.Description)
	link := fmt.Sprintf("/projects/%d", projectID)
	for _, m := range members {
		if !isApproverRole(m.RoleName) {
			continue
		}
		c.notify(ctx, m.UserID, EventAnomalyDetected, title, msg, &pid, link)
	}
	return nil
}
