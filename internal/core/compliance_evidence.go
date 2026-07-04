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
//
// #256: this used to compute the posture via GetCompliancePosture, then
// INDEPENDENTLY re-query every one of the same underlying signals a second time
// below (risk exceptions, SoD violations, the audit chain, rotation status,
// per-project campaigns/break-glass) with no transaction or snapshot isolation
// between the two passes. A concurrent write landing between them (a role granted,
// a secret rotated, an SoD violation created/resolved) could make the resulting
// pack's sections mutually inconsistent, even though it gets HMAC-signed as one
// atomic point-in-time attestation. Both the posture and every section below now
// come from ONE complianceSnapshot fetched once at the top — there is no second,
// independently-timed query left to diverge from the first.
func (c *KeyorixCore) GenerateComplianceEvidence(ctx context.Context) (*ComplianceEvidence, error) {
	snap, err := c.buildComplianceSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	posture := c.compliancePostureFromSnapshot(ctx, snap)

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

	// Active risk exceptions (the governed-acceptance register) — the snapshot's one
	// ListRiskExceptions(ctx, true) read, shared with the posture's own risk rollup
	// and its SoD-exception suppression above, not a second query.
	//
	// #136: each evidence section below previously had the same no-else fail-open
	// shape: a query error silently left the evidence-pack slice empty,
	// indistinguishable from "queried, found none" in the HMAC-signed pack an
	// auditor trusts. Every failure here still flips the shared posture.Degraded
	// signal via posture.degrade, so a consumer checking ev.Posture.Degraded catches
	// evidence-pack-level failures too, not just posture-rollup ones.
	if snap.riskExceptionsErr == nil {
		ev.RiskExceptions = snap.riskExceptionsActive
	} else {
		posture.degrade("evidence:risk_exceptions", snap.riskExceptionsErr)
	}

	// Separation-of-duties violations (the toxic-combination register) — shared with
	// the posture's own SoD rollup, not a second DetectSoDViolations scan.
	if snap.sodErr == nil {
		ev.SoDViolations = snap.sodReport.Violations
		// #420: a principal whose permissions couldn't be read means this register
		// may be missing a violation for them — flip the shared posture.Degraded
		// signal so an evidence-pack consumer catches it, same as every other
		// sub-query above.
		for _, reason := range snap.sodReport.DegradedReasons {
			posture.degrade("evidence:sod_violations", fmt.Errorf("%s", reason))
		}
	} else {
		posture.degrade("evidence:sod_violations", snap.sodErr)
	}

	// Audit anchor — shared with the posture's own AuditIntegrity, not a second
	// VerifyAuditChain call.
	if snap.auditChainErr == nil && snap.auditChain != nil {
		v := snap.auditChain
		ev.AuditAnchor = AuditAnchor{
			Valid: v.Valid, ChainedEvents: v.ChainedEvents,
			HeadID: v.HeadID, HeadHash: v.HeadHash, Checkpointed: v.Checkpointed,
		}
	} else if snap.auditChainErr != nil {
		posture.degrade("evidence:audit_anchor", snap.auditChainErr)
	}

	// Overdue rotations (deployment-wide) — shared with the posture's own Rotation
	// rollup, not a second GetRotationStatus scan.
	if snap.rotationErr == nil {
		for _, s := range snap.rotationStatuses {
			if s.Status == RotationStatusOverdue {
				ev.RotationOverdue = append(ev.RotationOverdue, EvidenceRotation{
					SecretID: s.SecretID, SecretName: s.SecretName,
					PolicyName: s.PolicyName, DaysOverdue: s.DaysOverdue,
				})
			}
		}
	} else {
		posture.degrade("evidence:rotation_overdue", snap.rotationErr)
	}

	// Campaigns + break-glass register, per project — shared with the posture's own
	// AccessGovernance/EmergencyAccess per-project loop, not a second query per
	// project.
	for _, proj := range snap.projects {
		pid := proj.ID
		if camps, err := snap.campaignsByProject[pid], snap.campaignsErrByProject[pid]; err == nil {
			for _, cw := range camps {
				ev.Campaigns = append(ev.Campaigns, EvidenceCampaign{
					ProjectID: pid, ID: cw.Campaign.ID, Name: cw.Campaign.Name,
					State: cw.Campaign.State, CreatedAt: cw.Campaign.CreatedAt, ClosedAt: cw.Campaign.ClosedAt,
					Total: cw.Progress.Total, Attested: cw.Progress.Attested,
					Revoked: cw.Progress.Revoked, Pending: cw.Progress.Pending,
				})
			}
		} else {
			posture.degrade(fmt.Sprintf("evidence:campaigns:project=%d", pid), err)
		}
		if acts, err := snap.breakGlassByProject[pid], snap.breakGlassErrByProject[pid]; err == nil {
			ev.BreakGlass = append(ev.BreakGlass, acts...)
		} else {
			posture.degrade(fmt.Sprintf("evidence:break_glass:project=%d", pid), err)
		}
	}
	return ev, nil
}
