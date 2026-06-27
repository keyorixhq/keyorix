// compliance_evidence.go — an auditor evidence pack (ISO 27001 / SOC 2 / NIS2 /
// DORA / ENS). Where GetCompliancePosture (compliance_posture.go) is the at-a-glance
// summary, GenerateComplianceEvidence bundles the posture together with the
// supporting records that substantiate it — the tamper-evidence audit anchor, the
// access-recertification campaigns, the break-glass register, and the overdue
// rotations — as one timestamped, archivable object an auditor can keep.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AuditAnchor is the tamper-evidence anchor of the audit hash chain (ADR-029): an
// auditor records (chained_events, head_hash) externally to detect later truncation.
type AuditAnchor struct {
	Valid         bool   `json:"valid"`
	ChainedEvents int64  `json:"chained_events"`
	HeadID        uint   `json:"head_id"`
	HeadHash      string `json:"head_hash"`
	Checkpointed  bool   `json:"checkpointed"`
}

// EvidenceCampaign is one access-recertification campaign in the evidence pack: the
// "we reviewed access" record (closed campaigns are completed reviews).
type EvidenceCampaign struct {
	ProjectID uint       `json:"project_id"`
	ID        uint       `json:"id"`
	Name      string     `json:"name"`
	State     string     `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	Total     int        `json:"total"`
	Attested  int        `json:"attested"`
	Revoked   int        `json:"revoked"`
	Pending   int        `json:"pending"`
}

// EvidenceRotation is one secret overdue for rotation (an open hygiene gap).
type EvidenceRotation struct {
	ProjectID   uint   `json:"project_id,omitempty"`
	SecretID    uint   `json:"secret_id"`
	SecretName  string `json:"secret_name"`
	PolicyName  string `json:"policy_name"`
	DaysOverdue int    `json:"days_overdue"`
}

// ComplianceEvidence is the auditor evidence pack at a point in time.
type ComplianceEvidence struct {
	GeneratedAt     time.Time                      `json:"generated_at"`
	Posture         *CompliancePosture             `json:"posture"`
	Controls        []ControlState                 `json:"controls"` // framework matrix (ISO/SOC2/NIS2/DORA/ENS)
	AuditAnchor     AuditAnchor                    `json:"audit_anchor"`
	Campaigns       []EvidenceCampaign             `json:"campaigns"`
	BreakGlass      []*models.BreakGlassActivation `json:"break_glass"`
	RotationOverdue []EvidenceRotation             `json:"rotation_overdue"`
	SoDViolations   []SoDViolation                 `json:"sod_violations"`
	RiskExceptions  []*RiskExceptionView           `json:"risk_exceptions"` // active governed exceptions (A.5.8)
}

// GenerateComplianceEvidence assembles the evidence pack. Like the posture, it is an
// on-demand admin export that walks every project.
func (c *KeyorixCore) GenerateComplianceEvidence(ctx context.Context) (*ComplianceEvidence, error) {
	posture, err := c.GetCompliancePosture(ctx)
	if err != nil {
		return nil, err
	}
	ev := &ComplianceEvidence{
		GeneratedAt:     c.now(),
		Posture:         posture,
		Controls:        EvaluateControls(posture),
		Campaigns:       []EvidenceCampaign{},
		BreakGlass:      []*models.BreakGlassActivation{},
		RotationOverdue: []EvidenceRotation{},
		SoDViolations:   []SoDViolation{},
		RiskExceptions:  []*RiskExceptionView{},
	}

	// Active risk exceptions (the governed-acceptance register).
	if exceptions, err := c.ListRiskExceptions(ctx, true); err == nil {
		ev.RiskExceptions = exceptions
	}

	// Separation-of-duties violations (the toxic-combination register).
	if violations, err := c.DetectSoDViolations(ctx); err == nil {
		ev.SoDViolations = violations
	}

	// Audit anchor.
	if v, err := c.VerifyAuditChain(ctx); err == nil && v != nil {
		ev.AuditAnchor = AuditAnchor{
			Valid: v.Valid, ChainedEvents: v.ChainedEvents,
			HeadID: v.HeadID, HeadHash: v.HeadHash, Checkpointed: v.Checkpointed,
		}
	}

	// Overdue rotations (deployment-wide).
	if statuses, err := c.GetRotationStatus(ctx, nil, nil); err == nil {
		for _, s := range statuses {
			if s.Status == RotationStatusOverdue {
				ev.RotationOverdue = append(ev.RotationOverdue, EvidenceRotation{
					SecretID: s.SecretID, SecretName: s.SecretName,
					PolicyName: s.PolicyName, DaysOverdue: s.DaysOverdue,
				})
			}
		}
	}

	// Campaigns + break-glass register, per project.
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, proj := range projects {
		pid := proj.ID
		if camps, err := c.ListAccessReviewCampaigns(ctx, pid); err == nil {
			for _, cw := range camps {
				ev.Campaigns = append(ev.Campaigns, EvidenceCampaign{
					ProjectID: pid, ID: cw.Campaign.ID, Name: cw.Campaign.Name,
					State: cw.Campaign.State, CreatedAt: cw.Campaign.CreatedAt, ClosedAt: cw.Campaign.ClosedAt,
					Total: cw.Progress.Total, Attested: cw.Progress.Attested,
					Revoked: cw.Progress.Revoked, Pending: cw.Progress.Pending,
				})
			}
		}
		if acts, err := c.ListBreakGlassActivations(ctx, pid); err == nil {
			ev.BreakGlass = append(ev.BreakGlass, acts...)
		}
	}
	return ev, nil
}
