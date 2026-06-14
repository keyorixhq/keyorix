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

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventAnomalyDetected is the audit event type emitted for each anomaly pushed out;
// it flows through the SIEM forwarder like any audit event.
const EventAnomalyDetected = "security.anomaly_detected" // #nosec G101 -- audit event type, not a credential

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

		// In-app: alert the project's approver-role members.
		c.notifyAnomalyAdmins(ctx, projectID, a)

		if err := c.storage.MarkAnomalyAlertAlerted(ctx, a.ID); err != nil {
			// Couldn't mark alerted — skip counting so a retry re-announces rather
			// than silently dropping (the audit event is already out, harmless dup).
			continue
		}
		announced++
	}
	return announced, nil
}

// notifyAnomalyAdmins sends an in-app alert to the project's approver-role members
// (best-effort). With no resolvable project the in-app notify is skipped (the audit
// + SIEM event still carries it).
func (c *KeyorixCore) notifyAnomalyAdmins(ctx context.Context, projectID uint, a *models.AnomalyAlert) {
	if projectID == 0 {
		return
	}
	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		return
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
}
