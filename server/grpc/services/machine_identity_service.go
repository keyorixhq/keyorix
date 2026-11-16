package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/errclass"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// MachineIdentityGRPCService implements pb.MachineIdentityServiceServer (ADR-023/030).
// Authz mirrors the HTTP routes: list → users.read, every mutation → roles.assign,
// scoped to the target project.
type MachineIdentityGRPCService struct {
	pb.UnimplementedMachineIdentityServiceServer
	core *core.KeyorixCore
}

var _ pb.MachineIdentityServiceServer = (*MachineIdentityGRPCService)(nil)

// NewMachineIdentityService creates the service backed by the shared core.
func NewMachineIdentityService(coreService *core.KeyorixCore) *MachineIdentityGRPCService {
	return &MachineIdentityGRPCService{core: coreService}
}

// mapMachineError translates core/storage machine-identity errors into gRPC status
// codes through the shared classifier (coreErrorStatus); the texts stay this family's
// own and fixed (GRPC-004: never a state name or classification enum value).
func mapMachineError(err error) error {
	texts := coreErrorTexts{errclass.PermissionDenied: "access denied"}
	switch {
	case errors.Is(err, core.ErrMachineIdentityNotFound):
		texts[errclass.NotFound] = "machine identity or token not found"
	case errors.Is(err, core.ErrMachineTransitionInvalid):
		texts[errclass.Precondition] = "invalid state transition"
	case errors.Is(err, core.ErrMachineIdentityNotActive):
		texts[errclass.Precondition] = "machine identity is not active"
	}
	// MACH-001: the privilege-ceiling denial (requireMachinePrivilegeCeiling) is a typed
	// permission sentinel, so the classifier answers it PermissionDenied, not Internal.
	return coreErrorStatus(context.Background(), err, coreErrorStatusOpts{op: "machine identity operation", texts: texts})
}

func machineActionToState(action string) (string, bool) {
	switch action {
	case "activate":
		return core.MachineActive, true
	case "suspend":
		return core.MachineSuspended, true
	case "revoke":
		return core.MachineRevoked, true
	default:
		return "", false
	}
}

func (s *MachineIdentityGRPCService) ListMachineIdentities(ctx context.Context, req *pb.ListMachineIdentitiesRequest) (*pb.ListMachineIdentitiesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "users.read", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	rows, err := s.core.ListMachineIdentities(ctx, uint(req.GetProjectId()))
	if err != nil {
		return nil, mapMachineError(err)
	}
	out := make([]*pb.MachineIdentity, 0, len(rows))
	for _, m := range rows {
		out = append(out, machineIdentityToProto(m))
	}
	return &pb.ListMachineIdentitiesResponse{MachineIdentities: out}, nil
}

func (s *MachineIdentityGRPCService) CreateMachineIdentity(ctx context.Context, req *pb.CreateMachineIdentityRequest) (*pb.MachineIdentity, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "project_id and name are required")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	m, err := s.core.CreateMachineIdentity(ctx, uint(req.GetProjectId()), req.GetName(), req.GetIdentityType(), req.GetDescription(), req.GetClassification(), user.UserID, user.MachineIdentityID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineIdentityToProto(m), nil
}

func (s *MachineIdentityGRPCService) TransitionMachineIdentity(ctx context.Context, req *pb.TransitionMachineIdentityRequest) (*pb.MachineIdentity, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	to, ok := machineActionToState(req.GetAction())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "action must be activate, suspend, or revoke")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	m, err := s.core.TransitionMachineIdentity(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), to, user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineIdentityToProto(m), nil
}

func (s *MachineIdentityGRPCService) ClassifyMachineIdentity(ctx context.Context, req *pb.ClassifyMachineIdentityRequest) (*pb.MachineIdentity, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	m, err := s.core.ClassifyMachineIdentity(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), req.GetClassification(), user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineIdentityToProto(m), nil
}

func (s *MachineIdentityGRPCService) IssueMachineToken(ctx context.Context, req *pb.IssueMachineTokenRequest) (*pb.IssueMachineTokenResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	expiresAt, err := core.MachineTokenExpiresAt(int64(req.GetExpiresInDays()), time.Now())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error()) // nosemgrep: keyorix-raw-error-to-client -- MachineTokenExpiresAt returns only a fixed ErrInvalidInput message built from the MaxMachineTokenLifetimeDays constant, never backend/driver text
	}
	if user.ActorKind() == core.ActorTypeMachine {
		// A directly authenticated machine acting as itself: core evaluates the
		// privilege ceiling against this machine, not against user 0, and
		// refuses a caller whose own credential is restricted or federated.
		ctx = core.WithSelfMachineGranter(ctx, user.PrincipalID())
		ctx = core.WithMachineCallerCredential(ctx, presentedBearerToken(ctx))
	}
	res, err := s.core.IssueMachineToken(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), user.UserID, core.IssueMachineTokenParams{
		Name:           req.GetName(),
		ExpiresAt:      expiresAt,
		Classification: req.GetClassification(),
	})
	if err != nil {
		return nil, mapMachineError(err)
	}
	return &pb.IssueMachineTokenResponse{
		Token:          res.PlainToken,
		Id:             intToU32(int(res.Credential.ID)),
		Prefix:         res.Credential.TokenPrefix,
		ExpiresAt:      timePtrToTs(res.Credential.ExpiresAt),
		Classification: res.Credential.Classification,
	}, nil
}

// presentedBearerToken returns the bearer token the request authenticated
// with, parsed the way the auth interceptor parses it (the first
// "authorization" metadata value, "Bearer " prefix), or "" when there is none.
func presentedBearerToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 || !strings.HasPrefix(vals[0], "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(vals[0], "Bearer ")
}

func (s *MachineIdentityGRPCService) ListMachineTokens(ctx context.Context, req *pb.ListMachineTokensRequest) (*pb.ListMachineTokensResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, "users.read", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	rows, err := s.core.ListMachineTokens(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()))
	if err != nil {
		return nil, mapMachineError(err)
	}
	out := make([]*pb.MachineToken, 0, len(rows))
	for _, c := range rows {
		out = append(out, machineTokenToProto(c))
	}
	return &pb.ListMachineTokensResponse{Tokens: out}, nil
}

func (s *MachineIdentityGRPCService) RevokeMachineToken(ctx context.Context, req *pb.RevokeMachineTokenRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 || req.GetTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id, machine_id and token_id are required")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	// core.RevokeMachineToken does not evict the HTTP positive-auth cache itself (see
	// its doc comment); no explicit eviction call is needed here either, because
	// middleware.serveAuthCacheHit re-validates every machine-token cache HIT against
	// storage (CurrentMachineTokenRestriction: cred.Revoked / expiry / identity state)
	// on every request, transport-agnostically — a revoke driven from gRPC is caught on
	// the very next HTTP request regardless of which transport performed it. Proven
	// non-vacuous in TestGRPCRevokeMachineToken_EvictsHTTPAuthCacheImmediately.
	if _, err := s.core.RevokeMachineToken(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), uint(req.GetTokenId()), user.UserID); err != nil {
		return nil, mapMachineError(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *MachineIdentityGRPCService) ClassifyMachineToken(ctx context.Context, req *pb.ClassifyMachineTokenRequest) (*pb.MachineToken, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 || req.GetTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id, machine_id and token_id are required")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	cred, err := s.core.ClassifyMachineToken(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), uint(req.GetTokenId()), req.GetClassification(), user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineTokenToProto(cred), nil
}
