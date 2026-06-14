// control_framework.go — the compliance control matrix (ISO 27001 / SOC 2 / NIS2 /
// DORA). Where GetCompliancePosture reports raw figures, GetComplianceControls maps
// each control Keyorix enforces to its clause references across the regimes an
// auditor cares about, and evaluates a live status (pass / gap / not-configured)
// from the posture. It turns the scattered A.5.x tiles into one auditor-ready
// framework map. Read-only; gated by system.read.
package core

import (
	"context"
	"fmt"
	"time"
)

// ControlStatus is a control's evaluated state.
type ControlStatus string

const (
	ControlStatusPass          ControlStatus = "pass"
	ControlStatusGap           ControlStatus = "gap"
	ControlStatusNotConfigured ControlStatus = "not_configured"
)

// FrameworkRefs maps a control to clauses across the regimes Keyorix targets.
type FrameworkRefs struct {
	ISO27001 []string `json:"iso_27001,omitempty"` // Annex A:2022 control ids, e.g. "A.5.18"
	SOC2     []string `json:"soc2,omitempty"`      // Trust Services Criteria, e.g. "CC6.1"
	NIS2     []string `json:"nis2,omitempty"`      // article refs, e.g. "Art.21(2)(i)"
	DORA     []string `json:"dora,omitempty"`      // article refs, e.g. "Art.9"
}

// ControlState is one control's evaluated posture for the framework matrix.
type ControlState struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Area       string        `json:"area"`
	Status     ControlStatus `json:"status"`
	Detail     string        `json:"detail"`
	Frameworks FrameworkRefs `json:"frameworks"`
}

// ControlsSummary tallies controls by status.
type ControlsSummary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Gap           int `json:"gap"`
	NotConfigured int `json:"not_configured"`
}

// ComplianceControls is the evaluated control matrix at a point in time.
type ComplianceControls struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Controls    []ControlState  `json:"controls"`
	Summary     ControlsSummary `json:"summary"`
}

// GetComplianceControls evaluates the control matrix from the current posture.
func (c *KeyorixCore) GetComplianceControls(ctx context.Context) (*ComplianceControls, error) {
	p, err := c.GetCompliancePosture(ctx)
	if err != nil {
		return nil, err
	}
	controls := EvaluateControls(p)
	out := &ComplianceControls{GeneratedAt: c.now(), Controls: controls}
	out.Summary.Total = len(controls)
	for _, ctrl := range controls {
		switch ctrl.Status {
		case ControlStatusPass:
			out.Summary.Pass++
		case ControlStatusGap:
			out.Summary.Gap++
		case ControlStatusNotConfigured:
			out.Summary.NotConfigured++
		}
	}
	return out, nil
}

// gapIf returns Gap when bad is true, else Pass — the common two-state evaluation.
func gapIf(bad bool) ControlStatus {
	if bad {
		return ControlStatusGap
	}
	return ControlStatusPass
}

// EvaluateControls derives the control matrix from a posture snapshot. It is a pure
// function (no storage) so the mapping and status logic are unit-testable in
// isolation. The order is stable (grouped by area) for a deterministic report.
func EvaluateControls(p *CompliancePosture) []ControlState {
	ag := p.AccessGovernance
	return []ControlState{
		{
			ID: "audit-trail-integrity", Name: "Tamper-evident audit trail", Area: "Audit & accountability",
			Status:     gapIf(!p.AuditIntegrity.ChainVerified),
			Detail:     fmt.Sprintf("chain verified=%t, checkpointed=%t, %d events", p.AuditIntegrity.ChainVerified, p.AuditIntegrity.Checkpointed, p.AuditIntegrity.ChainedEvents),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.28", "A.8.15"}, SOC2: []string{"CC7.2", "CC4.1"}, NIS2: []string{"Art.21(2)(i)"}, DORA: []string{"Art.9"}},
		},
		{
			ID: "access-recertification", Name: "Access recertification at planned intervals", Area: "Access governance",
			Status:     gapIf(ag.ProjectsOverdue > 0 || ag.ProjectsNeverReviewed > 0),
			Detail:     fmt.Sprintf("%d overdue, %d never reviewed, %d pending items", ag.ProjectsOverdue, ag.ProjectsNeverReviewed, ag.PendingItems),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.18"}, SOC2: []string{"CC6.2", "CC6.3"}, NIS2: []string{"Art.21(2)(i)"}, DORA: []string{"Art.9"}},
		},
		{
			ID: "dormant-access", Name: "No dormant standing access", Area: "Access governance",
			Status:     gapIf(ag.DormantRoleGrants > 0),
			Detail:     fmt.Sprintf("%d dormant role grant(s)", ag.DormantRoleGrants),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.18", "A.8.2"}, SOC2: []string{"CC6.1"}},
		},
		{
			ID: "separation-of-duties", Name: "Separation of duties (no toxic combinations)", Area: "Access governance",
			Status:     gapIf(ag.SoDViolations > 0),
			Detail:     fmt.Sprintf("%d SoD violation(s)", ag.SoDViolations),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.3"}, SOC2: []string{"CC5.1"}, DORA: []string{"Art.5"}},
		},
		{
			ID: "second-factor", Name: "Second-factor coverage", Area: "Identity",
			Status:     gapIf(p.Identity.SecondFactorPercent < 100),
			Detail:     fmt.Sprintf("%d%% of active users have a second factor", p.Identity.SecondFactorPercent),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.17", "A.8.5"}, SOC2: []string{"CC6.1"}, NIS2: []string{"Art.21(2)(j)"}, DORA: []string{"Art.9"}},
		},
		{
			ID: "secret-rotation", Name: "Secret-rotation hygiene", Area: "Cryptography",
			Status:     gapIf(p.Rotation.Overdue > 0),
			Detail:     fmt.Sprintf("%d overdue, %d due soon of %d covered", p.Rotation.Overdue, p.Rotation.DueSoon, p.Rotation.CoveredSecrets),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.15", "A.8.24"}, SOC2: []string{"CC6.1"}, NIS2: []string{"Art.21(2)(h)"}},
		},
		{
			ID: "data-classification", Name: "Secret data classification", Area: "Asset management",
			Status:     gapIf(p.Classification.Unclassified > 0),
			Detail:     fmt.Sprintf("%d of %d secrets unclassified", p.Classification.Unclassified, p.Classification.TotalSecrets),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.12", "A.5.13"}, SOC2: []string{"CC3.2"}},
		},
		{
			ID: "anomaly-detection", Name: "Access-anomaly detection & response", Area: "Detection",
			Status:     gapIf(p.Anomalies.HighSeverityOpen > 0),
			Detail:     fmt.Sprintf("%d open anomalies (%d high severity)", p.Anomalies.Unacknowledged, p.Anomalies.HighSeverityOpen),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.8.16"}, SOC2: []string{"CC7.2", "CC7.3"}, NIS2: []string{"Art.21(2)(b)"}, DORA: []string{"Art.10"}},
		},
		{
			ID: "emergency-access", Name: "Governed emergency (break-glass) access", Area: "Access governance",
			Status:     ControlStatusPass, // presence of the register is the control; usage is informational
			Detail:     fmt.Sprintf("%d active, %d total activations (all audited)", p.EmergencyAccess.ActiveActivations, p.EmergencyAccess.TotalActivations),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.15"}, SOC2: []string{"CC6.1"}, DORA: []string{"Art.9"}},
		},
		{
			ID: "data-retention", Name: "Data-retention / storage limitation", Area: "Data governance",
			Status:     statusFromBool(p.Retention.Enabled),
			Detail:     retentionDetail(p.Retention),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.33"}, SOC2: []string{"CC3.2"}, DORA: []string{"Art.12"}},
		},
		{
			ID: "legal-hold", Name: "Litigation/investigation legal hold", Area: "Data governance",
			Status:     ControlStatusPass, // capability present; active state is informational
			Detail:     legalHoldDetail(p.LegalHold),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.34"}, DORA: []string{"Art.12"}},
		},
	}
}

// statusFromBool maps an enabled flag to pass / not-configured (an unset optional
// control is "not configured" rather than a gap — it may not apply to every install).
func statusFromBool(enabled bool) ControlStatus {
	if enabled {
		return ControlStatusPass
	}
	return ControlStatusNotConfigured
}

func retentionDetail(r RetentionPosture) string {
	if !r.Enabled {
		return "no retention windows configured (records kept indefinitely)"
	}
	return fmt.Sprintf("windows set: anomaly=%dd, reviews=%dd, break-glass=%dd, requests=%dd",
		r.AnomalyAlertsDays, r.ClosedAccessReviewsDays, r.BreakGlassDays, r.ResolvedAccessRequestsDays)
}

func legalHoldDetail(h LegalHoldPosture) string {
	if h.Active {
		return fmt.Sprintf("ACTIVE — purges blocked (%s)", h.Reason)
	}
	return "available; none currently active"
}
