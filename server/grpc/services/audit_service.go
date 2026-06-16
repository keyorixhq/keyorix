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

// Audit-stream tail tuning: a SAFETY-NET fallback interval (the common path is the
// push signal from core.SubscribeAuditStream, not this) and the max events drained per
// wake. The interval is a var so tests can shorten it.
var auditStreamFallbackInterval = 30 * time.Second

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
	if err := authorizeGlobal(ctx, s.core, actor, "audit.read"); err != nil {
		return nil, err
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
	if err := authorizeGlobal(ctx, s.core, actor, "audit.read"); err != nil {
		return nil, err
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
// (events created after the stream opens — use GetAuditLogs for history), applying
// the same event_type/user/project filters. It is PUSH-driven: an in-process broker
// wakes the stream the instant an event is written (core.SubscribeAuditStream), then
// the stream drains the new rows from its forward id cursor (AuditFilter.AfterID/
// Ascending). The database stays authoritative — the signal only collapses latency, so
// no event is lost to a slow consumer. A long fallback ticker is a safety net for any
// write that did not signal (e.g. a path that bypasses the audit funnel). The stream
// ends when the client disconnects (context cancellation).
func (s *AuditGRPCService) StreamAuditLogs(req *pb.StreamAuditLogsRequest, stream pb.AuditService_StreamAuditLogsServer) error {
	ctx := stream.Context()
	actor := interceptors.GetUserFromGRPCContext(ctx)
	if actor == nil {
		return status.Error(codes.Unauthenticated, "user not authenticated")
	}
	if err := authorizeGlobal(ctx, s.core, actor, "audit.read"); err != nil {
		return err
	}

	// Subscribe BEFORE reading the head id so no write between the two is missed: a
	// write in that window leaves a pending tick, and the first drain queries from the
	// head cursor anyway.
	subID, wake := s.core.SubscribeAuditStream()
	defer s.core.UnsubscribeAuditStream(subID)

	// Resume from a client-supplied cursor (gap-free reconnect): start just after
	// after_id and replay the backlog before tailing live. Default (0/unset) starts at
	// the current head, tailing only new events.
	var cursor uint
	if req.AfterId != nil && req.GetAfterId() > 0 {
		cursor = uint(req.GetAfterId())
	} else {
		head, err := s.latestAuditID(ctx)
		if err != nil {
			return status.Error(codes.Internal, "failed to start audit stream")
		}
		cursor = head
	}

	fallback := time.NewTicker(auditStreamFallbackInterval)
	defer fallback.Stop()

	// Replay any backlog after the resume cursor immediately, then block for live ticks.
	drain := func() error {
		for {
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
				return nil
			}
			names := s.core.ResolveUsernames(ctx, events)
			for _, e := range events {
				if err := stream.Send(auditEventToProto(e, names)); err != nil {
					return err // client gone / send failed
				}
				cursor = e.ID
			}
			// A full page may mean more is queued; loop until the cursor catches up.
			if len(events) < auditStreamBatch {
				return nil
			}
		}
	}

	// Deliver the resume backlog (if any) before waiting for live events; for the
	// default head-start cursor this is a no-op.
	if err := drain(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
			if err := drain(); err != nil {
				return err
			}
		case <-fallback.C:
			if err := drain(); err != nil {
				return err
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
