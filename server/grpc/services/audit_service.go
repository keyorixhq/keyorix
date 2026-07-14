package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)


// Audit-stream tail tuning: a SAFETY-NET fallback interval (the common path is the
// push signal from core.SubscribeAuditStream, not this) and the max events drained per
// wake. The interval is a var so tests can shorten it. The SAME interval re-validates
// the stream's authorization (#108): StreamAuthInterceptor authenticates a stream once
// at open and is never re-run by the normal per-request path, so a session/PAT
// revoked, a role removed, or an account suspended/deprovisioned mid-stream would
// otherwise keep receiving the live audit feed until the client disconnects on its
// own — potentially indefinitely.
var auditStreamFallbackInterval = 30 * time.Second

const auditStreamBatch = 100

// auditStreamMaxPerPrincipal bounds how many concurrent StreamAuditLogs a single
// principal may hold open — an unbounded caller could otherwise open arbitrarily many
// streams, each subscribed to the audit broker, amplifying the fan-out cost of every
// audit write across the whole install (auditBroker.signal iterates every subscriber
// under one lock).
const auditStreamMaxPerPrincipal = 3

// AuditGRPCService implements pb.AuditServiceServer.
type AuditGRPCService struct {
	pb.UnimplementedAuditServiceServer
	core *core.KeyorixCore

	streamCountsMu sync.Mutex
	streamCounts   map[string]int // "kind:id" -> concurrently open StreamAuditLogs calls
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.AuditServiceServer = (*AuditGRPCService)(nil)

// NewAuditService creates an audit gRPC service backed by the shared core.
func NewAuditService(coreService *core.KeyorixCore) *AuditGRPCService {
	return &AuditGRPCService{core: coreService, streamCounts: make(map[string]int)}
}

// acquireStreamSlot reserves one of a principal's auditStreamMaxPerPrincipal
// concurrent StreamAuditLogs slots, refusing a new stream once the cap is reached.
// The returned release func MUST be deferred by the caller to free the slot.
func (s *AuditGRPCService) acquireStreamSlot(actor *interceptors.UserContext) (func(), error) {
	key := fmt.Sprintf("%s:%d", actor.ActorKind(), actor.PrincipalID())
	s.streamCountsMu.Lock()
	defer s.streamCountsMu.Unlock()
	if s.streamCounts[key] >= auditStreamMaxPerPrincipal {
		return nil, status.Errorf(codes.ResourceExhausted,
			"too many concurrent audit streams for this principal (max %d)", auditStreamMaxPerPrincipal)
	}
	s.streamCounts[key]++
	return func() {
		s.streamCountsMu.Lock()
		defer s.streamCountsMu.Unlock()
		s.streamCounts[key]--
		if s.streamCounts[key] <= 0 {
			delete(s.streamCounts, key)
		}
	}, nil
}

// reauthorizeAuditStream re-validates that actor may still hold this live audit feed:
// the audit.read permission (a role/grant revoked mid-stream) and, since a long-lived
// stream is authenticated once at open and never re-run by the per-request path, that
// the underlying principal itself is still active — a user account that was
// suspended/deprovisioned/deleted, or a machine identity that was suspended/revoked.
// A stale-but-still-role-holding actor (e.g. a session or PAT that isn't THIS user's
// only credential) is not distinguishable without the raw token, which the stream
// context does not retain — the account- and role-level checks close the practical
// admin-action revocation paths (suspend, deprovision, delete, remove role) #108
// describes.
func (s *AuditGRPCService) reauthorizeAuditStream(ctx context.Context, actor *interceptors.UserContext) error {
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
		return err
	}
	if actor.ActorKind() == core.ActorTypeMachine {
		m, err := s.core.Storage().GetMachineIdentity(ctx, actor.MachineIdentityID)
		if err != nil || m.State != core.MachineActive {
			return status.Error(codes.PermissionDenied, "machine identity is no longer active")
		}
		return nil
	}
	u, err := s.core.Storage().GetUser(ctx, actor.UserID)
	if err != nil || !u.IsActive || core.AccountLoginBlocked(u.AccountState) {
		return status.Error(codes.PermissionDenied, "account is no longer active")
	}
	return nil
}

// GetAuditLogs reads the audit log with filtering and pagination.
func (s *AuditGRPCService) GetAuditLogs(ctx context.Context, req *pb.GetAuditLogsRequest) (*pb.GetAuditLogsResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
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
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
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

// VerifyAuditChain re-walks the tamper-evidence hash chain (ADR-029) and reports
// whether the trail is intact. Mirrors GET /api/v1/audit/verify; requires audit.read.
func (s *AuditGRPCService) VerifyAuditChain(ctx context.Context, _ *emptypb.Empty) (*pb.VerifyAuditChainResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
		return nil, err
	}
	v, err := s.core.VerifyAuditChain(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to verify audit chain")
	}
	resp := &pb.VerifyAuditChainResponse{
		Valid:            v.Valid,
		ChainedEvents:    v.ChainedEvents,
		UnchainedEvents:  v.UnchainedEvents,
		HeadHash:         v.HeadHash,
		HeadId:           intToU32(int(v.HeadID)),
		Checkpointed:     v.Checkpointed,
		Reason:           v.Reason,
		CheckpointReason: v.CheckpointReason,
	}
	if v.FirstBrokenID != nil {
		resp.FirstBrokenId = ptrU32(*v.FirstBrokenID)
	}
	return resp, nil
}

// WriteAuditCheckpoint signs a checkpoint of the verified audit-chain head on demand
// (ADR-029). Mirrors POST /api/v1/audit/checkpoint; privileged (system.write). Returns
// FailedPrecondition when the chain does not verify or encryption is disabled.
func (s *AuditGRPCService) WriteAuditCheckpoint(ctx context.Context, _ *emptypb.Empty) (*pb.WriteAuditCheckpointResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "system.write"); err != nil {
		return nil, err
	}
	cp, written, err := s.core.WriteAuditCheckpoint(ctx)
	if err != nil {
		// The chain did not verify (broken, or a prior signed checkpoint proves a
		// truncation) — refuse to notarise it. A precondition failure, not an error.
		// core.WriteAuditCheckpoint also propagates raw storage-layer errors on this
		// path, which must not reach the client verbatim.
		msg := err.Error()
		if !strings.Contains(msg, "refusing to checkpoint") {
			log.Printf("Error writing audit checkpoint: %v", err)
			msg = clientSafe(err)
		}
		return nil, status.Error(codes.FailedPrecondition, msg)
	}
	if !written {
		return nil, status.Error(codes.FailedPrecondition,
			"signed audit checkpoints require encryption to be enabled (the signing key is derived from the DEK)")
	}
	resp := &pb.WriteAuditCheckpointResponse{
		Id:             intToU32(int(cp.ID)),
		ChainedEvents:  cp.ChainedEvents,
		HeadId:         intToU32(int(cp.HeadID)),
		HeadHash:       cp.HeadHash,
		KeyVersion:     cp.KeyVersion,
		AnchorProvider: cp.AnchorProvider,
	}
	if cp.AnchoredAt != nil {
		resp.AnchoredAt = timestamppb.New(*cp.AnchoredAt)
	}
	return resp, nil
}

// GetAuditRetention reports the audit trail's retention coverage (NIS2 12-month).
// Mirrors GET /api/v1/audit/retention; requires audit.read.
func (s *AuditGRPCService) GetAuditRetention(ctx context.Context, _ *emptypb.Empty) (*pb.GetAuditRetentionResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
		return nil, err
	}
	cov, err := s.core.AuditRetentionCoverage(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to compute audit retention coverage")
	}
	resp := &pb.GetAuditRetentionResponse{
		RetentionPolicy:   cov.RetentionPolicy,
		TotalEvents:       cov.TotalEvents,
		CoverageDays:      int64(cov.CoverageDays),
		MeetsNis2_12Month: cov.MeetsNIS2TwelveMonth,
	}
	if cov.OldestEvent != nil {
		resp.OldestEvent = timestamppb.New(*cov.OldestEvent)
	}
	if cov.NewestEvent != nil {
		resp.NewestEvent = timestamppb.New(*cov.NewestEvent)
	}
	return resp, nil
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
func (s *AuditGRPCService) StreamAuditLogs(req *pb.StreamAuditLogsRequest, stream pb.AuditService_StreamAuditLogsServer) error { // NOSONAR -- cognitive complexity 38, suppress go:S3776
	ctx := stream.Context()
	actor := interceptors.GetUserFromGRPCContext(ctx)
	if actor == nil {
		return status.Error(codes.Unauthenticated, "user not authenticated")
	}
	if err := authorizeGlobal(ctx, s.core, actor, permAuditRead); err != nil {
		return err
	}
	release, err := s.acquireStreamSlot(actor)
	if err != nil {
		return err
	}
	defer release()

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
			// Re-validate authorization on every fallback tick (#108): a permission
			// revoked, or the account/machine identity itself deactivated, since the
			// stream opened must end the feed within one interval, not only when the
			// client eventually disconnects on its own.
			if err := s.reauthorizeAuditStream(ctx, actor); err != nil {
				return err
			}
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
