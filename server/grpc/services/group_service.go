package services

import (
	"context"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GroupGRPCService implements pb.GroupServiceServer over the shared core. It enforces
// the SAME global permissions as the HTTP routes: reads → users.read, group CRUD →
// users.write, membership changes → roles.assign (adding a member confers every role
// the group holds — the same blast radius as a role grant).
type GroupGRPCService struct {
	pb.UnimplementedGroupServiceServer
	core *core.KeyorixCore
}

var _ pb.GroupServiceServer = (*GroupGRPCService)(nil)

// NewGroupService creates a group gRPC service backed by the shared core.
func NewGroupService(coreService *core.KeyorixCore) *GroupGRPCService {
	return &GroupGRPCService{core: coreService}
}

func (s *GroupGRPCService) ListGroups(ctx context.Context, _ *emptypb.Empty) (*pb.ListGroupsResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.read"); err != nil {
		return nil, err
	}
	groups, err := s.core.ListGroups(ctx)
	if err != nil {
		return nil, groupError(err)
	}
	out := make([]*pb.Group, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupToProto(g))
	}
	return &pb.ListGroupsResponse{Groups: out}, nil
}

func (s *GroupGRPCService) GetGroup(ctx context.Context, req *pb.GetGroupRequest) (*pb.Group, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.read"); err != nil {
		return nil, err
	}
	g, err := s.core.GetGroup(ctx, uint(req.GetId()))
	if err != nil {
		return nil, groupError(err)
	}
	return groupToProto(g), nil
}

func (s *GroupGRPCService) CreateGroup(ctx context.Context, req *pb.CreateGroupRequest) (*pb.Group, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.write"); err != nil {
		return nil, err
	}
	g, err := s.core.CreateGroup(ctx, actor.UserID, &core.CreateGroupRequest{
		Name: req.GetName(), Description: req.GetDescription(),
	})
	if err != nil {
		return nil, groupError(err)
	}
	return groupToProto(g), nil
}

func (s *GroupGRPCService) UpdateGroup(ctx context.Context, req *pb.UpdateGroupRequest) (*pb.Group, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.write"); err != nil {
		return nil, err
	}
	g, err := s.core.UpdateGroup(ctx, actor.UserID, &core.UpdateGroupRequest{
		ID: uint(req.GetId()), Name: req.GetName(), Description: req.GetDescription(),
	})
	if err != nil {
		return nil, groupError(err)
	}
	return groupToProto(g), nil
}

func (s *GroupGRPCService) DeleteGroup(ctx context.Context, req *pb.DeleteGroupRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.write"); err != nil {
		return nil, err
	}
	if err := s.core.DeleteGroup(ctx, actor.UserID, uint(req.GetId())); err != nil {
		return nil, groupError(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *GroupGRPCService) RestoreGroup(ctx context.Context, req *pb.RestoreGroupRequest) (*pb.Group, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.write"); err != nil {
		return nil, err
	}
	if err := s.core.RestoreGroup(ctx, actor.UserID, uint(req.GetId())); err != nil {
		return nil, groupError(err)
	}
	g, err := s.core.GetGroup(ctx, uint(req.GetId()))
	if err != nil {
		return nil, groupError(err)
	}
	return groupToProto(g), nil
}

func (s *GroupGRPCService) GetGroupMembers(ctx context.Context, req *pb.GetGroupMembersRequest) (*pb.GetGroupMembersResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.read"); err != nil {
		return nil, err
	}
	users, err := s.core.GetGroupMembers(ctx, uint(req.GetId()))
	if err != nil {
		return nil, groupError(err)
	}
	out := make([]*pb.GroupMember, 0, len(users))
	for _, u := range users {
		out = append(out, groupMemberToProto(u))
	}
	return &pb.GetGroupMembersResponse{Members: out}, nil
}

func (s *GroupGRPCService) AddGroupMember(ctx context.Context, req *pb.GroupMemberRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "roles.assign"); err != nil {
		return nil, err
	}
	if err := s.core.AddUserToGroup(ctx, uint(req.GetUserId()), uint(req.GetGroupId())); err != nil {
		return nil, groupError(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *GroupGRPCService) RemoveGroupMember(ctx context.Context, req *pb.GroupMemberRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "roles.assign"); err != nil {
		return nil, err
	}
	if err := s.core.RemoveUserFromGroup(ctx, uint(req.GetUserId()), uint(req.GetGroupId())); err != nil {
		return nil, groupError(err)
	}
	return &emptypb.Empty{}, nil
}

func groupToProto(g *models.Group) *pb.Group {
	return &pb.Group{
		Id:          intToU32(int(g.ID)),
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   timestamppb.New(g.CreatedAt),
		UpdatedAt:   timestamppb.New(g.UpdatedAt),
	}
}

func groupMemberToProto(u *models.User) *pb.GroupMember {
	return &pb.GroupMember{
		Id:          intToU32(int(u.ID)),
		Username:    u.Username,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Active:      u.IsActive,
	}
}

// groupError maps a core error to a gRPC status, mirroring the HTTP status codes.
func groupError(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, err.Error())
	case strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate") || strings.Contains(msg, "in use"):
		return status.Error(codes.AlreadyExists, err.Error())
	case strings.Contains(msg, "required") || strings.Contains(msg, "invalid") || strings.Contains(msg, "exceeds"):
		return status.Error(codes.InvalidArgument, err.Error())
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		return status.Error(codes.Internal, "group operation failed")
	}
}
