package services

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuditGRPCService implements pb.AuditServiceServer. StreamAuditLogs has no
// backing yet, so it is left as the embedded Unimplemented default.
type AuditGRPCService struct {
	pb.UnimplementedAuditServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.AuditServiceServer = (*AuditGRPCService)(nil)

// NewAuditService creates an audit gRPC service backed by the shared core.
func NewAuditService(coreService *core.KeyorixCore) *AuditGRPCService {
	return &AuditGRPCService{core: coreService}
}

// GetAuditLogs reads the audit log with filtering and pagination.
func (s *AuditGRPCService) GetAuditLogs(ctx context.Context, req *pb.GetAuditLogsRequest) (*pb.GetAuditLogsResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "audit.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read audit logs")
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())

	filter := &corestorage.AuditFilter{
		Action:    optString(req.EventType),
		UserID:    optUint(req.UserId),
		ProjectID: optUint(req.ProjectId),
		ActorType: optString(req.ActorType),
		StartTime: tsToTimePtr(req.GetStartTime()),
		EndTime:   tsToTimePtr(req.GetEndTime()),
		Page:      page,
		PageSize:  pageSize,
	}

	events, total, err := s.core.Storage().GetAuditLogs(ctx, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to read audit logs")
	}
	names := s.core.ResolveUsernames(ctx, events)

	logs := make([]*pb.AuditLog, 0, len(events))
	for _, e := range events {
		logs = append(logs, auditEventToProto(e, names))
	}
	return &pb.GetAuditLogsResponse{
		Logs:       logs,
		Total:      i64ToU32(total),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(int(total), pageSize)),
	}, nil
}

// GetRBACAuditLogs returns the RBAC audit trail (role assignments/removals).
func (s *AuditGRPCService) GetRBACAuditLogs(ctx context.Context, req *pb.GetRBACAuditLogsRequest) (*pb.GetRBACAuditLogsResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "audit.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read audit logs")
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())

	entries, total, err := s.core.ListRBACAuditLogs(ctx, page, pageSize)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to read RBAC audit logs")
	}

	logs := make([]*pb.RBACAuditLog, 0, len(entries))
	for _, e := range entries {
		logs = append(logs, rbacEntryToProto(e))
	}
	return &pb.GetRBACAuditLogsResponse{
		Logs:       logs,
		Total:      i64ToU32(total),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(int(total), pageSize)),
	}, nil
}

func rbacEntryToProto(e *core.RBACAuditEntry) *pb.RBACAuditLog {
	out := &pb.RBACAuditLog{
		Id:        intToU32(int(e.ID)),
		Action:    e.Action,
		Details:   e.Details,
		CreatedAt: timestamppb.New(e.CreatedAt),
	}
	if e.ActorUserID != nil {
		out.ActorUserId = ptrU32(*e.ActorUserID)
	}
	if e.TargetUserID != nil {
		out.TargetUserId = ptrU32(*e.TargetUserID)
	}
	if e.RoleID != nil {
		out.RoleId = ptrU32(*e.RoleID)
	}
	if e.ProjectID != nil {
		out.ProjectId = ptrU32(*e.ProjectID)
	}
	return out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func auditEventToProto(e *models.AuditEvent, names map[uint]string) *pb.AuditLog {
	success := true
	if e.Success != nil {
		success = *e.Success
	}
	out := &pb.AuditLog{
		Id:            intToU32(int(e.ID)),
		EventType:     e.EventType,
		Actor:         resolveActor(e, names),
		ActorType:     e.ActorType,
		Description:   e.Description,
		IpAddress:     e.IPAddress,
		Success:       success,
		EventTime:     timestamppb.New(e.EventTime),
		Impersonation: e.Impersonation,
		Diff:          optStringValue(e.Diff),
	}
	if e.UserID != nil {
		out.UserId = ptrU32(*e.UserID)
	}
	if e.ProjectID != nil {
		out.ProjectId = ptrU32(*e.ProjectID)
	}
	if e.SecretNodeID != nil {
		out.SecretId = ptrU32(*e.SecretNodeID)
	}
	if e.ImpersonatedBy != nil {
		out.ImpersonatedBy = optStringValue(names[*e.ImpersonatedBy])
	}
	if e.ActingAs != nil {
		out.ActingAs = optStringValue(names[*e.ActingAs])
	}
	return out
}

// resolveActor returns the actor's username, or "system"/"unknown" when there is
// no resolvable user.
func resolveActor(e *models.AuditEvent, names map[uint]string) string {
	if e.UserID == nil {
		if e.ActorType == "system" {
			return "system"
		}
		return "unknown"
	}
	if n, ok := names[*e.UserID]; ok && n != "" {
		return n
	}
	return "unknown"
}

func ptrU32(v uint) *uint32 {
	x := intToU32(int(v))
	return &x
}
