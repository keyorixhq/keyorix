package services

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ComplianceGRPCService implements pb.ComplianceServiceServer — the read-only
// compliance posture + control-matrix surface over gRPC (mirrors the HTTP/CLI
// reports). Both RPCs require an authenticated user with global audit.read.
type ComplianceGRPCService struct {
	pb.UnimplementedComplianceServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.ComplianceServiceServer = (*ComplianceGRPCService)(nil)

// NewComplianceService creates a compliance gRPC service.
func NewComplianceService(coreService *core.KeyorixCore) *ComplianceGRPCService {
	return &ComplianceGRPCService{core: coreService}
}

// GetCompliancePosture returns the deployment-wide controls-posture snapshot.
func (s *ComplianceGRPCService) GetCompliancePosture(ctx context.Context, _ *emptypb.Empty) (*pb.CompliancePosture, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
		return nil, err
	}
	p, err := s.core.GetCompliancePosture(ctx)
	if err != nil {
		return nil, err
	}
	return compliancePostureToProto(p), nil
}

// GetComplianceControls returns the evaluated control matrix.
func (s *ComplianceGRPCService) GetComplianceControls(ctx context.Context, _ *emptypb.Empty) (*pb.ComplianceControls, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
		return nil, err
	}
	c, err := s.core.GetComplianceControls(ctx)
	if err != nil {
		return nil, err
	}
	return complianceControlsToProto(c), nil
}

// compliancePostureToProto maps the core posture roll-up to its protobuf form.
func compliancePostureToProto(p *core.CompliancePosture) *pb.CompliancePosture {
	if p == nil {
		return nil
	}
	out := &pb.CompliancePosture{
		GeneratedAt: timestamppb.New(p.GeneratedAt),
		AuditIntegrity: &pb.AuditIntegrityPosture{
			ChainVerified: p.AuditIntegrity.ChainVerified,
			ChainedEvents: p.AuditIntegrity.ChainedEvents,
			Checkpointed:  p.AuditIntegrity.Checkpointed,
			Reason:        p.AuditIntegrity.Reason,
		},
		AccessGovernance: &pb.AccessGovernancePosture{
			Projects:                 intToI32(p.AccessGovernance.Projects),
			ProjectsWithOpenCampaign: intToI32(p.AccessGovernance.ProjectsWithOpenCampaign),
			ProjectsNeverReviewed:    intToI32(p.AccessGovernance.ProjectsNeverReviewed),
			OpenCampaigns:            intToI32(p.AccessGovernance.OpenCampaigns),
			PendingItems:             intToI32(p.AccessGovernance.PendingItems),
			ProjectsOverdue:          intToI32(p.AccessGovernance.ProjectsOverdue),
			DormantRoleGrants:        intToI32(p.AccessGovernance.DormantRoleGrants),
			SodViolations:            intToI32(p.AccessGovernance.SoDViolations),
		},
		Rotation: &pb.RotationPosture{
			CoveredSecrets: intToI32(p.Rotation.CoveredSecrets),
			Overdue:        intToI32(p.Rotation.Overdue),
			DueSoon:        intToI32(p.Rotation.DueSoon),
		},
		Identity: &pb.IdentityPosture{
			ActiveUsers:           intToI32(p.Identity.ActiveUsers),
			UsersWithSecondFactor: intToI32(p.Identity.UsersWithSecondFactor),
			SecondFactorPercent:   intToI32(p.Identity.SecondFactorPercent),
		},
		EmergencyAccess: &pb.EmergencyAccessPosture{
			ActiveActivations: intToI32(p.EmergencyAccess.ActiveActivations),
			TotalActivations:  intToI32(p.EmergencyAccess.TotalActivations),
		},
		Classification: &pb.ClassificationPosture{
			TotalSecrets:       intToI32(p.Classification.TotalSecrets),
			Public:             intToI32(p.Classification.Public),
			Internal:           intToI32(p.Classification.Internal),
			Confidential:       intToI32(p.Classification.Confidential),
			Restricted:         intToI32(p.Classification.Restricted),
			Unclassified:       intToI32(p.Classification.Unclassified),
			DynamicConfigs:     classificationCountsToProto(p.Classification.DynamicConfigs),
			MachineIdentities:  classificationCountsToProto(p.Classification.MachineIdentities),
			MachineCredentials: classificationCountsToProto(p.Classification.MachineCredentials),
		},
		Anomalies: &pb.AnomaliesPosture{
			Unacknowledged:   intToI32(p.Anomalies.Unacknowledged),
			HighSeverityOpen: intToI32(p.Anomalies.HighSeverityOpen),
		},
		LegalHold: &pb.LegalHoldPosture{
			Active: p.LegalHold.Active,
			Reason: p.LegalHold.Reason,
		},
		Retention: &pb.RetentionPosture{
			Enabled:                    p.Retention.Enabled,
			AnomalyAlertsDays:          intToI32(p.Retention.AnomalyAlertsDays),
			ClosedAccessReviewsDays:    intToI32(p.Retention.ClosedAccessReviewsDays),
			BreakGlassDays:             intToI32(p.Retention.BreakGlassDays),
			ResolvedAccessRequestsDays: intToI32(p.Retention.ResolvedAccessRequestsDays),
		},
		Risk: &pb.RiskPosture{
			ActiveExceptions: intToI32(p.Risk.ActiveExceptions),
			ExpiringSoon:     intToI32(p.Risk.ExpiringSoon),
		},
		// #136: Degraded/DegradedReasons must reach every consumer, gRPC included —
		// silently dropping them here would leave gRPC callers unable to distinguish
		// a genuinely clean snapshot from one where a sub-rollup query failed.
		Degraded:        p.Degraded,
		DegradedReasons: p.DegradedReasons,
	}
	if p.LegalHold.PlacedAt != nil {
		out.LegalHold.PlacedAt = timestamppb.New(*p.LegalHold.PlacedAt)
	}
	return out
}

func classificationCountsToProto(c core.ClassificationCounts) *pb.ClassificationCounts {
	return &pb.ClassificationCounts{
		Total:        intToI32(c.Total),
		Public:       intToI32(c.Public),
		Internal:     intToI32(c.Internal),
		Confidential: intToI32(c.Confidential),
		Restricted:   intToI32(c.Restricted),
		Unclassified: intToI32(c.Unclassified),
	}
}

// complianceControlsToProto maps the core control matrix to its protobuf form.
func complianceControlsToProto(c *core.ComplianceControls) *pb.ComplianceControls {
	if c == nil {
		return nil
	}
	controls := make([]*pb.ControlState, 0, len(c.Controls))
	for _, ctl := range c.Controls {
		controls = append(controls, &pb.ControlState{
			Id:     ctl.ID,
			Name:   ctl.Name,
			Area:   ctl.Area,
			Status: string(ctl.Status),
			Detail: ctl.Detail,
			Frameworks: &pb.FrameworkRefs{
				Iso_27001: ctl.Frameworks.ISO27001,
				Soc2:      ctl.Frameworks.SOC2,
				Nis2:      ctl.Frameworks.NIS2,
				Dora:      ctl.Frameworks.DORA,
				Ens:       ctl.Frameworks.ENS,
			},
		})
	}
	return &pb.ComplianceControls{
		GeneratedAt: timestamppb.New(c.GeneratedAt),
		Controls:    controls,
		Summary: &pb.ControlsSummary{
			Total:         intToI32(c.Summary.Total),
			Pass:          intToI32(c.Summary.Pass),
			Gap:           intToI32(c.Summary.Gap),
			NotConfigured: intToI32(c.Summary.NotConfigured),
			Unknown:       intToI32(c.Summary.Unknown),
		},
	}
}
