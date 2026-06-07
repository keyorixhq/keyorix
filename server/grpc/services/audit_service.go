package services

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Audit-stream tail tuning: how often to poll for new events, and the max events
// drained per poll. The interval is a var so tests can shorten it.
var auditStreamPollInterval = 2 * time.Second

const auditStreamBatch = 100

// AuditGRPCService implements pb.AuditServiceServer.
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
	if e.GroupID != nil {
		out.GroupId = ptrU32(*e.GroupID)
	}
	if e.PermissionID != nil {
		out.PermissionId = ptrU32(*e.PermissionID)
	}
	if e.RoleID != nil {
		out.RoleId = ptrU32(*e.RoleID)
	}
	if e.ProjectID != nil {
		out.ProjectId = ptrU32(*e.ProjectID)
	}
	return out
}

// StreamAuditLogs tails the audit log: it streams audit events as they occur
// (events created after the stream opens — use GetAuditLogs for history),
// applying the same event_type/user/project filters. Implemented by polling the
// forward id cursor (AuditFilter.AfterID/Ascending) every auditStreamPollInterval,
// which avoids a separate pub/sub broker and reuses the existing query path. The
// stream ends when the client disconnects (context cancellation).
func (s *AuditGRPCService) StreamAuditLogs(req *pb.StreamAuditLogsRequest, stream pb.AuditService_StreamAuditLogsServer) error {
	ctx := stream.Context()
	actor := interceptors.GetUserFromGRPCContext(ctx)
	if actor == nil {
		return status.Error(codes.Unauthenticated, "user not authenticated")
	}
	if !hasPermission(actor.Permissions, "audit.read") {
		return status.Error(codes.PermissionDenied, "insufficient permissions to read audit logs")
	}

	// Start at the current head so we tail new events, not the backlog.
	cursor, err := s.latestAuditID(ctx)
	if err != nil {
		return status.Error(codes.Internal, "failed to start audit stream")
	}

	ticker := time.NewTicker(auditStreamPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			after := cursor
			events, _, err := s.core.Storage().GetAuditLogs(ctx, &corestorage.AuditFilter{
				AfterID:   &after,
				Ascending: true,
				PageSize:  auditStreamBatch,
				Action:    optString(req.EventType),
				UserID:    optUint(req.UserId),
				ProjectID: optUint(req.ProjectId),
			})
			if err != nil {
				return status.Error(codes.Internal, "failed to read audit logs")
			}
			if len(events) == 0 {
				continue
			}
			names := s.core.ResolveUsernames(ctx, events)
			for _, e := range events {
				if err := stream.Send(auditEventToProto(e, names)); err != nil {
					return err // client gone / send failed
				}
				cursor = e.ID
			}
		}
	}
}

// latestAuditID returns the most recent audit event id (the tail starting point),
// or 0 when the log is empty. The default GetAuditLogs order is newest-first and
// ids autoincrement with insertion, so the first row carries the head id.
func (s *AuditGRPCService) latestAuditID(ctx context.Context) (uint, error) {
	events, _, err := s.core.Storage().GetAuditLogs(ctx, &corestorage.AuditFilter{Page: 1, PageSize: 1})
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	return events[0].ID, nil
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
