// compliance_digest.go — a scheduled compliance digest (ISO 27001 / SOC 2 continuous
// monitoring): a periodic summary of the control matrix + posture (controls
// pass/gap, overdue recertifications, rotation gaps, unclassified secrets, open
// anomalies, active risk exceptions) broadcast to the configured notification
// channels (Slack/Teams/webhook). It ties the control matrix to the notification
// fan-out so an admin sees the deployment's compliance state where they work,
// without opening the console.
package core

import (
	"context"
	"fmt"
	"log"
	"strings"
)

const EventComplianceDigestSent = "compliance.digest_sent"

// BuildComplianceDigest assembles the digest from the current posture + control
// matrix. Returns a title and a plaintext body.
func (c *KeyorixCore) BuildComplianceDigest(ctx context.Context) (title, body string, err error) {
	p, err := c.GetCompliancePosture(ctx)
	if err != nil {
		return "", "", err
	}
	controls := EvaluateControls(p)
	title, body = formatComplianceDigest(p, controls)
	return title, body, nil
}

// formatComplianceDigest renders the digest from a posture snapshot + evaluated
// controls. Pure (no storage) so it is unit-testable.
func formatComplianceDigest(p *CompliancePosture, controls []ControlState) (title, body string) {
	pass, gap, unknown := 0, 0, 0
	var gaps, unknowns []string
	for _, ctrl := range controls {
		switch ctrl.Status {
		case ControlStatusPass:
			pass++
		case ControlStatusGap:
			gap++
			gaps = append(gaps, ctrl.Name)
		case ControlStatusUnknown:
			unknown++
			unknowns = append(unknowns, ctrl.Name)
		}
	}

	// #136: a degraded snapshot must be the headline, not a footnote — a collection
	// failure means this digest is incomplete, and a reader skimming Slack/Teams must
	// not read "N/N controls pass" as a clean bill of health when it isn't one.
	switch {
	case p.Degraded:
		title = fmt.Sprintf("Keyorix compliance digest — INCOMPLETE (%d control(s) unknown, collection error)", unknown)
	case gap > 0:
		title = fmt.Sprintf("Keyorix compliance digest — %d gap%s across %d controls", gap, plural(gap), len(controls))
	default:
		title = fmt.Sprintf("Keyorix compliance digest — %d/%d controls pass", pass, len(controls))
	}

	var b strings.Builder
	ag := p.AccessGovernance
	if p.Degraded {
		fmt.Fprintf(&b, "WARNING: this snapshot is DEGRADED — %d control(s) could not be collected this run and read as UNKNOWN, not verified-clean: %s.\n",
			unknown, strings.Join(unknowns, ", "))
		fmt.Fprintf(&b, "Collection failures: %s.\n", strings.Join(p.DegradedReasons, "; "))
	}
	fmt.Fprintf(&b, "Controls: %d pass, %d gap, %d unknown (of %d).\n", pass, gap, unknown, len(controls))
	if gap > 0 {
		fmt.Fprintf(&b, "Open gaps: %s.\n", strings.Join(gaps, ", "))
	}
	fmt.Fprintf(&b, "Access: %d project(s) overdue for recertification, %d never reviewed, %d SoD violation(s), %d dormant grant(s).\n",
		ag.ProjectsOverdue, ag.ProjectsNeverReviewed, ag.SoDViolations, ag.DormantRoleGrants)
	fmt.Fprintf(&b, "Rotation: %d overdue, %d due soon. Second factor: %d%% of active users.\n",
		p.Rotation.Overdue, p.Rotation.DueSoon, p.Identity.SecondFactorPercent)
	fmt.Fprintf(&b, "Classification: %d of %d secrets unclassified. Anomalies: %d open (%d high).\n",
		p.Classification.Unclassified, p.Classification.TotalSecrets, p.Anomalies.Unacknowledged, p.Anomalies.HighSeverityOpen)
	fmt.Fprintf(&b, "Risk register: %d active exception(s) (%d expiring soon).",
		p.Risk.ActiveExceptions, p.Risk.ExpiringSoon)
	if p.LegalHold.Active {
		b.WriteString("\nA legal hold is ACTIVE — purges are blocked.")
	}
	return title, b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// SendComplianceDigest builds the digest and broadcasts it to the configured
// notification channels (Slack/Teams/webhook/email). It is a single broadcast (no
// per-user fan-out), so a chat channel gets one message. Returns whether the digest
// was actually attempted (false when no notification channel is wired at all, OR
// every wired channel was a no-op — e.g. an email-only deployment with no
// email.broadcast_to destination configured, #221). Audited either way, but the
// audit event only claims success when delivery was actually attempted.
func (c *KeyorixCore) SendComplianceDigest(ctx context.Context) (bool, error) {
	if c.notificationSink == nil {
		return false, nil // nowhere to deliver — no channel configured
	}
	title, body, err := c.BuildComplianceDigest(ctx)
	if err != nil {
		return false, err
	}
	attempted := c.notificationSink.Deliver(NotificationEvent{
		Type:    "compliance.digest",
		Title:   title,
		Message: body,
		Link:    "/compliance",
	})
	sysCtx := WithActorType(ctx, ActorTypeSystem)
	if !attempted {
		log.Printf("compliance digest: notification channel(s) configured but none accepted the broadcast (e.g. email-only with no broadcast destination) — digest was NOT delivered")
		c.writeAuditEventFailed(sysCtx, EventComplianceDigestSent, nil, "", "compliance digest broadcast attempted but no configured channel could accept it")
		return false, nil
	}
	c.writeAuditEvent(sysCtx, EventComplianceDigestSent, nil, nil, "compliance digest broadcast to notification channels")
	return true, nil
}
