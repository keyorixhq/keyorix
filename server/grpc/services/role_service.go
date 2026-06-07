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
)

// RoleGRPCService implements pb.RoleServiceServer, backing each RPC with the
// shared core service (role CRUD + permission wiring via storage, reads via the
// core RBAC helpers).
type RoleGRPCService struct {
	pb.UnimplementedRoleServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.RoleServiceServer = (*RoleGRPCService)(nil)

// NewRoleService creates a role gRPC service backed by the shared core.
func NewRoleService(coreService *core.KeyorixCore) *RoleGRPCService {
	return &RoleGRPCService{core: coreService}
}

// CreateRole creates a role and assigns its permission set.
func (s *RoleGRPCService) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.Role, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to create roles")
	}
	if req.GetName() == "" || req.GetDescription() == "" || len(req.GetPermissions()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "name, description and at least one permission are required")
	}

	permIDs, err := s.resolvePermissionIDs(ctx, req.GetPermissions())
	if err != nil {
		return nil, err
	}

	role, err := s.core.Storage().CreateRole(ctx, &models.Role{Name: req.GetName(), Description: req.GetDescription()})
	if err != nil {
		return nil, mapRoleError(err)
	}
	for _, pid := range permIDs {
		if err := s.core.AssignPermissionToRole(ctx, actor.UserID, role.ID, pid); err != nil {
			return nil, status.Error(codes.Internal, "failed to assign permissions to role")
		}
	}
	return s.roleByID(ctx, role.ID)
}

// GetRole returns a role with its permissions.
func (s *RoleGRPCService) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read roles")
	}
	return s.roleByID(ctx, uint(req.GetId()))
}

// UpdateRole updates a role's description and/or replaces its permission set.
func (s *RoleGRPCService) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.Role, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to update roles")
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	role, current, err := s.core.GetRoleWithPermissions(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapRoleError(err)
	}

	if req.Description != nil {
		role.Description = req.GetDescription()
		if _, err := s.core.Storage().UpdateRole(ctx, role); err != nil {
			return nil, mapRoleError(err)
		}
	}

	// A provided permission list replaces the entire set.
	if len(req.GetPermissions()) > 0 {
		permIDs, err := s.resolvePermissionIDs(ctx, req.GetPermissions())
		if err != nil {
			return nil, err
		}
		for _, p := range current {
			if err := s.core.RemovePermissionFromRole(ctx, actor.UserID, role.ID, p.ID); err != nil {
				return nil, status.Error(codes.Internal, "failed to update role permissions")
			}
		}
		for _, pid := range permIDs {
			if err := s.core.AssignPermissionToRole(ctx, actor.UserID, role.ID, pid); err != nil {
				return nil, status.Error(codes.Internal, "failed to update role permissions")
			}
		}
	}

	return s.roleByID(ctx, role.ID)
}

// DeleteRole deletes a role.
func (s *RoleGRPCService) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to delete roles")
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := s.core.Storage().DeleteRole(ctx, uint(req.GetId())); err != nil {
		return nil, mapRoleError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListRoles lists roles with their permissions, paginated in memory.
func (s *RoleGRPCService) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to list roles")
	}

	all, err := s.core.ListRolesWithPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list roles")
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	total := len(all)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	out := make([]*pb.Role, 0, end-start)
	for _, rwp := range all[start:end] {
		r := rwp.Role
		out = append(out, roleToProto(&r, rwp.Permissions))
	}
	return &pb.ListRolesResponse{
		Roles:      out,
		Total:      intToU32(total),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(total, pageSize)),
	}, nil
}

// AssignRole assigns a role to a user at an optional project/environment scope.
func (s *RoleGRPCService) AssignRole(ctx context.Context, req *pb.AssignRoleRequest) (*pb.RoleAssignment, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.assign") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to assign roles")
	}
	if req.GetUserId() == 0 || req.GetRoleId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if err := s.core.AssignUserRole(ctx, actor.UserID, uint(req.GetUserId()), uint(req.GetRoleId()), scope); err != nil {
		return nil, mapRoleError(err)
	}
	return &pb.RoleAssignment{
		UserId:        req.GetUserId(),
		RoleId:        req.GetRoleId(),
		ProjectId:     req.GetProjectId(),
		EnvironmentId: req.GetEnvironmentId(),
	}, nil
}

// RemoveRole removes a role assignment from a user.
func (s *RoleGRPCService) RemoveRole(ctx context.Context, req *pb.RemoveRoleRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.assign") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to remove role assignments")
	}
	if req.GetUserId() == 0 || req.GetRoleId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if err := s.core.RemoveUserRole(ctx, actor.UserID, uint(req.GetUserId()), uint(req.GetRoleId()), scope); err != nil {
		return nil, mapRoleError(err)
	}
	return &emptypb.Empty{}, nil
}

// GetUserRoles returns all roles assigned to a user.
func (s *RoleGRPCService) GetUserRoles(ctx context.Context, req *pb.GetUserRolesRequest) (*pb.GetUserRolesResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "roles.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read role assignments")
	}
	assignment, err := s.core.GetUserRoleAssignment(ctx, uint(req.GetUserId()))
	if err != nil {
		return nil, mapRoleError(err)
	}
	roles := make([]*pb.Role, 0, len(assignment.Roles))
	for _, r := range assignment.Roles {
		roles = append(roles, roleToProto(r, nil))
	}
	return &pb.GetUserRolesResponse{
		UserId:   intToU32(int(assignment.UserID)),
		Username: assignment.Username,
		Email:    assignment.Email,
		Roles:    roles,
	}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// roleByID fetches a role with its permissions and maps it to proto.
func (s *RoleGRPCService) roleByID(ctx context.Context, id uint) (*pb.Role, error) {
	role, perms, err := s.core.GetRoleWithPermissions(ctx, id)
	if err != nil {
		return nil, mapRoleError(err)
	}
	return roleToProto(role, perms), nil
}

// resolvePermissionIDs maps permission names to IDs, rejecting unknown names.
func (s *RoleGRPCService) resolvePermissionIDs(ctx context.Context, names []string) ([]uint, error) {
	perms, err := s.core.Storage().ListPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to resolve permissions")
	}
	byName := make(map[string]uint, len(perms))
	for _, p := range perms {
		byName[p.Name] = p.ID
	}
	ids := make([]uint, 0, len(names))
	for _, n := range names {
		id, ok := byName[n]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown permission %q", n)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func roleToProto(r *models.Role, perms []*models.Permission) *pb.Role {
	out := &pb.Role{
		Id:          intToU32(int(r.ID)),
		Name:        r.Name,
		Description: r.Description,
	}
	for _, p := range perms {
		out.Permissions = append(out.Permissions, permissionToProto(p))
	}
	return out
}

func permissionToProto(p *models.Permission) *pb.Permission {
	return &pb.Permission{
		Id:          intToU32(int(p.ID)),
		Name:        p.Name,
		Description: p.Description,
		Resource:    p.Resource,
		Action:      p.Action,
	}
}

// mapRoleError translates core/storage role errors into gRPC status codes.
func mapRoleError(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "role not found")
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "duplicate"), strings.Contains(msg, "unique"):
		return status.Error(codes.AlreadyExists, "a role with that name already exists")
	default:
		return status.Error(codes.Internal, "role operation failed")
	}
}
