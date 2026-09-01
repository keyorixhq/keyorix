package services

import (
	"context"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Role Name/Description length bounds. gRPC has no shared internal/core
// validation layer to inherit these from (unlike other resources), so they
// are mirrored here exactly from the HTTP-side struct tags in
// server/http/handlers/rbac.go (CreateRoleRequest/UpdateRoleRequest) to keep
// the two transports' accepted input identical (#191).
const (
	roleNameMinLen        = 3
	roleNameMaxLen        = 50
	roleDescriptionMinLen = 1
	roleDescriptionMaxLen = 200
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
	if err := authorizeGlobal(ctx, s.core, actor, permRolesWrite); err != nil {
		return nil, err
	}
	if len(req.GetPermissions()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one permission is required")
	}
	if err := validateRoleName(req.GetName()); err != nil {
		return nil, err
	}
	if err := validateRoleDescription(req.GetDescription()); err != nil {
		return nil, err
	}
	// #1642: fold once here, use for both the reserved-name check below and
	// the CreateRole call — see the identical HTTP-side treatment
	// (RBACHandler.CreateRole) for the full rationale, including why folding
	// before IsBuiltinRole closes a case-variant gap that check's own exact
	// map lookup otherwise leaves open.
	foldedName, ferr := identity.NewFoldedName(req.GetName())
	if ferr != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid role name: "+ferr.Error())
	}
	// #294: reserved role names must never be creatable — see the identical guard (with
	// full rationale) in the HTTP RBACHandler.CreateRole. This closes the same gap over
	// gRPC, which has its own independent CreateRole path.
	if core.IsBuiltinRole(foldedName.Folded()) {
		return nil, status.Error(codes.AlreadyExists, "this role name is reserved and cannot be created")
	}

	permIDs, err := s.resolvePermissionIDs(ctx, actor.UserID, req.GetPermissions())
	if err != nil {
		return nil, err
	}

	role, err := s.core.Storage().CreateRole(ctx, foldedName, req.GetDescription())
	if err != nil {
		return nil, mapRoleError(err)
	}
	for _, pid := range permIDs {
		if err := s.core.AssignPermissionToRole(ctx, actor.UserID, role.ID, pid, false); err != nil {
			return nil, status.Error(codes.Internal, "failed to assign permissions to role")
		}
	}
	// Audit the role creation, mirroring the HTTP handler — Storage().CreateRole does
	// not audit internally, so without this a role created over gRPC left no trail.
	// (Permission grants are audited by AssignPermissionToRole itself.)
	s.core.LogRoleCreated(ctx, actor.UserID, role.ID, role.Name)
	return s.roleByID(ctx, role.ID)
}

// GetRole returns a role with its permissions.
func (s *RoleGRPCService) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesRead); err != nil {
		return nil, err
	}
	return s.roleByID(ctx, uint(req.GetId()))
}

// UpdateRole updates a role's description and/or replaces its permission set.
func (s *RoleGRPCService) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.Role, error) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesWrite); err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if req.Description != nil {
		if err := validateRoleDescription(req.GetDescription()); err != nil {
			return nil, err
		}
	}

	role, current, err := s.core.GetRoleWithPermissions(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapRoleError(err)
	}
	// A built-in role must not be mutable over gRPC either — mirrors the CreateRole/
	// DeleteRole guards above/below. UpdateRole unconditionally strips a role's entire
	// current permission set before re-adding the caller-supplied one (see below), so
	// without this check a roles.write holder could shrink e.g. admin/system_admin down
	// to whatever subset they hold themselves, silently locking out every administrator
	// who relies on that built-in role. The HTTP handler applies the identical guard
	// (handlers/rbac.go); without it here the guard is bypassable by switching transport.
	if core.IsBuiltinRole(role.Name) {
		s.core.LogRoleUpdateDenied(ctx, actor.UserID, role.ID, role.Name, "target is a built-in role")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot update built-in role: %s", role.Name)
	}

	if req.Description != nil {
		role.Description = req.GetDescription()
		if _, err := s.core.Storage().UpdateRole(ctx, role); err != nil {
			return nil, mapRoleError(err)
		}
	}

	// A provided permission list replaces the entire set.
	if len(req.GetPermissions()) > 0 {
		permIDs, err := s.resolvePermissionIDs(ctx, actor.UserID, req.GetPermissions())
		if err != nil {
			return nil, err
		}
		for _, p := range current {
			if err := s.core.RemovePermissionFromRole(ctx, actor.UserID, role.ID, p.ID); err != nil {
				return nil, status.Error(codes.Internal, "failed to update role permissions")
			}
		}
		for _, pid := range permIDs {
			if err := s.core.AssignPermissionToRole(ctx, actor.UserID, role.ID, pid, false); err != nil {
				return nil, status.Error(codes.Internal, "failed to update role permissions")
			}
		}
	}

	// Audit the role update, mirroring the HTTP handler — Storage().UpdateRole and the
	// permission swap above do not emit a role.updated event on their own.
	s.core.LogRoleUpdated(ctx, actor.UserID, role.ID, role.Name)
	return s.roleByID(ctx, role.ID)
}

// DeleteRole deletes a role.
func (s *RoleGRPCService) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesWrite); err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	// Resolve the name for the audit log before the row is gone (mirrors HTTP).
	role, _, err := s.core.GetRoleWithPermissions(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapRoleError(err)
	}
	// A built-in role must not be deletable over gRPC either — the HTTP handler
	// refuses it (handlers/rbac.go), and deleting e.g. super_admin/admin would
	// invalidate live assignments and can lock every administrator out. Without
	// this the guard is bypassable by switching transport.
	if core.IsBuiltinRole(role.Name) {
		s.core.LogRoleDeleteDenied(ctx, actor.UserID, role.ID, role.Name, "target is a built-in role")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot delete built-in role: %s", role.Name)
	}
	if err := s.core.Storage().DeleteRole(ctx, uint(req.GetId())); err != nil {
		return nil, mapRoleError(err)
	}
	// Audit the deletion — Storage().DeleteRole does not audit internally.
	s.core.LogRoleDeleted(ctx, actor.UserID, role.ID, role.Name)
	return &emptypb.Empty{}, nil
}

// ListRoles lists roles with their permissions, paginated in memory.
func (s *RoleGRPCService) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesRead); err != nil {
		return nil, err
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
	if req.GetUserId() == 0 || req.GetRoleId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}
	// Authorize roles.assign AT THE TARGET scope, not the flat global union — else a
	// project-A admin could grant roles into any project B (cross-project privesc).
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if err := authorizeScoped(ctx, s.core, actor, "roles.assign", scope); err != nil {
		return nil, err
	}
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
	if req.GetUserId() == 0 || req.GetRoleId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}
	// Authorize roles.assign at the target scope (see AssignRole) — not the flat union.
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if err := authorizeScoped(ctx, s.core, actor, "roles.assign", scope); err != nil {
		return nil, err
	}
	if err := s.core.RemoveUserRole(ctx, actor.UserID, uint(req.GetUserId()), uint(req.GetRoleId()), scope); err != nil {
		return nil, mapRoleError(err)
	}
	return &emptypb.Empty{}, nil
}

// GetUserRoles returns all roles assigned to a user. Calls the identical
// core.GetUserRoleAssignment the HTTP sibling RBACHandler.GetUserRoles does
// (server/http/handlers/rbac.go), which is deliberately routed behind
// permRolesAssign, not permRolesRead (server/http/router.go: GET
// /roles/user/{userId}) — a stricter permission than the roles.read that gates
// the rest of the /roles route group, because this discloses an arbitrary
// user's full role assignment (including admin-tier roles), which is
// reconnaissance for a targeted privilege-escalation attempt. Match that gate
// here (G16).
func (s *RoleGRPCService) GetUserRoles(ctx context.Context, req *pb.GetUserRolesRequest) (*pb.GetUserRolesResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesAssign); err != nil {
		return nil, err
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

// resolvePermissionIDs maps permission names to IDs, rejecting unknown names, and
// requires actorID already hold every named permission (#169: CreateRole/UpdateRole
// are gated only by the narrower permRolesWrite — without this, a roles.write holder
// could bundle an arbitrary admin-tier permission into a role's DEFINITION with no
// check they hold it themselves, mirroring the same check the HTTP handler applies).
// Checked at global scope, matching how roles.write itself is gated. Validating here
// — before the caller creates/mutates anything — means a request naming even one
// unauthorized permission is rejected atomically, not partially applied.
func (s *RoleGRPCService) resolvePermissionIDs(ctx context.Context, actorID uint, names []string) ([]uint, error) {
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
		authorized, aerr := s.core.Authorize(ctx, actorID, n, core.Scope{})
		if aerr != nil {
			return nil, status.Error(codes.Internal, "failed to resolve actor authority")
		}
		if !authorized {
			return nil, status.Errorf(codes.PermissionDenied, "cannot bundle permission %q into a role: you do not hold it yourself", n)
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

// validateRoleName mirrors HTTP's CreateRoleRequest.Name `min=3,max=50` bound
// (server/http/handlers/rbac.go) so a role name accepted over gRPC is never
// shorter/longer than one accepted over HTTP (#191).
func validateRoleName(name string) error {
	if len(name) < roleNameMinLen || len(name) > roleNameMaxLen {
		return status.Errorf(codes.InvalidArgument, "name must be between %d and %d characters", roleNameMinLen, roleNameMaxLen)
	}
	return nil
}

// validateRoleDescription mirrors HTTP's Role Description `min=1,max=200`
// bound (server/http/handlers/rbac.go) for the same reason (#191).
func validateRoleDescription(description string) error {
	if len(description) < roleDescriptionMinLen || len(description) > roleDescriptionMaxLen {
		return status.Errorf(codes.InvalidArgument, "description must be between %d and %d characters", roleDescriptionMinLen, roleDescriptionMaxLen)
	}
	return nil
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
