package services

// authzdiff_known01_read_gate_family_test.go -- the family-wide guard for
// INV-GRPCSVC-group-user-role-mutations-require-read-gate (authzdiff known-01).
//
// authzdiff_known01_read_gate_test.go pins one representative RPC per service;
// this file covers every RPC that gates through authorizeGlobalMutation, so
// reverting ANY one of them to authorizeGlobal(<write>) alone turns its subtest
// red. For each RPC two principals are built that differ ONLY in the read
// permission: "gate-only" holds the write/delete/assign permission plus the
// case's extras, "read-and-gate" holds the same plus the read permission. The
// first must get PermissionDenied, the second must succeed. Because the second
// principal succeeds, nothing after the gate denies that request, so the first
// principal's denial can only come from the missing read permission.
//
// TestGRPCMutations_ReadGateFamily_CoversEveryGatedRPC keeps the table complete:
// it parses the three service files and requires the set of methods calling
// authorizeGlobalMutation to equal the table's keys. What this does NOT catch:
// a NEW mutating RPC that never calls authorizeGlobalMutation in the first place
// (it is in neither set); the RPC-by-RPC list in the INV fragment and
// server/http/router.go's route groups are the reference for that.
import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// readGateCase is one RPC gated by authorizeGlobalMutation(read, gate).
type readGateCase struct {
	rpc    string   // "<Service>.<Method>", matched against the AST scan
	read   string   // the route group's outer read permission
	gate   string   // the per-RPC write/delete/assign permission
	extras []string // held by BOTH principals, so they are not the differential
	// setup builds the service and any target rows (as the admin, user 1) and
	// returns the call to make as the given principal.
	setup func(t *testing.T, h *testhelper.RBACTestHelper) func(ctx context.Context) error
}

const (
	readGateGateOnlyID    = 2
	readGateReadAndGateID = 3
)

// grantReadGatePrincipals creates the two principals for one case. Called
// before any auto-increment user is created so the explicit IDs cannot collide.
func grantReadGatePrincipals(t *testing.T, h *testhelper.RBACTestHelper, c readGateCase) {
	t.Helper()
	grant := func(userID uint, username string, roleID uint, perms []string) {
		h.CreateTestUser(t, username, userID)
		role := h.CreateTestRole(t, "readgate-"+username, "read-gate family fixture", roleID)
		for _, p := range perms {
			h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
				SELECT ?, id FROM permissions WHERE name = ?`, role.ID, p)
		}
		h.AssignUserRole(t, userID, role.ID, nil)
	}
	gateOnly := append([]string{c.gate}, c.extras...)
	grant(readGateGateOnlyID, "gate-only", 300, gateOnly)
	grant(readGateReadAndGateID, "read-and-gate", 301, append([]string{c.read}, gateOnly...))
}

func readGateFamilyCases() []readGateCase {
	newGroup := func(t *testing.T, svc *GroupGRPCService, name string) *pb.Group {
		t.Helper()
		g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: name})
		require.NoError(t, err)
		return g
	}
	newUser := func(t *testing.T, h *testhelper.RBACTestHelper) *UserGRPCService {
		t.Helper()
		h.CreateTestUser(t, "admin", 1)
		return NewUserService(h.CoreService)
	}
	// system.read for the user RPCs: every new user gets system_viewer, and the
	// permission-derived admin-authority ceiling would otherwise deny both
	// principals for a reason unrelated to the read gate.
	userExtras := []string{"system.read"}

	return []readGateCase{
		{rpc: "GroupGRPCService.CreateGroup", read: "users.read", gate: "users.write",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewGroupService(h.CoreService)
				return func(ctx context.Context) error {
					_, err := svc.CreateGroup(ctx, &pb.CreateGroupRequest{Name: "readgate-created"})
					return err
				}
			}},
		{rpc: "GroupGRPCService.UpdateGroup", read: "users.read", gate: "users.write",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewGroupService(h.CoreService)
				g := newGroup(t, svc, "readgate-update")
				return func(ctx context.Context) error {
					_, err := svc.UpdateGroup(ctx, &pb.UpdateGroupRequest{Id: g.GetId(), Name: g.GetName(), Description: "renamed"})
					return err
				}
			}},
		{rpc: "GroupGRPCService.DeleteGroup", read: "users.read", gate: "users.write",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewGroupService(h.CoreService)
				g := newGroup(t, svc, "readgate-delete")
				return func(ctx context.Context) error {
					_, err := svc.DeleteGroup(ctx, &pb.DeleteGroupRequest{Id: g.GetId()})
					return err
				}
			}},
		{rpc: "GroupGRPCService.RestoreGroup", read: "users.read", gate: "roles.assign",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewGroupService(h.CoreService)
				g := newGroup(t, svc, "readgate-restore")
				_, err := svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: g.GetId()})
				require.NoError(t, err)
				return func(ctx context.Context) error {
					_, err := svc.RestoreGroup(ctx, &pb.RestoreGroupRequest{Id: g.GetId()})
					return err
				}
			}},
		{rpc: "GroupGRPCService.AddGroupMember", read: "users.read", gate: "roles.assign",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewGroupService(h.CoreService)
				g := newGroup(t, svc, "readgate-addmember")
				member := h.CreateTestUser(t, "readgate-member", 60)
				return func(ctx context.Context) error {
					_, err := svc.AddGroupMember(ctx, &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: uint32(member.ID)})
					return err
				}
			}},
		{rpc: "GroupGRPCService.RemoveGroupMember", read: "users.read", gate: "roles.assign",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewGroupService(h.CoreService)
				g := newGroup(t, svc, "readgate-removemember")
				member := h.CreateTestUser(t, "readgate-member", 60)
				req := &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: uint32(member.ID)}
				_, err := svc.AddGroupMember(groupCtx(), req)
				require.NoError(t, err)
				return func(ctx context.Context) error {
					_, err := svc.RemoveGroupMember(ctx, req)
					return err
				}
			}},
		{rpc: "UserGRPCService.CreateUser", read: "users.read", gate: "users.write", extras: userExtras,
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := newUser(t, h)
				return func(ctx context.Context) error {
					_, err := svc.CreateUser(ctx, &pb.CreateUserRequest{
						Username: "readgate-new", Email: "readgate-new@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
					})
					return err
				}
			}},
		{rpc: "UserGRPCService.UpdateUser", read: "users.read", gate: "users.write", extras: userExtras,
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := newUser(t, h)
				target := svc.mustCreate(t, "readgate-target", "readgate-target@example.com")
				return func(ctx context.Context) error {
					_, err := svc.UpdateUser(ctx, &pb.UpdateUserRequest{Id: target.GetId(), DisplayName: strPtr("renamed")})
					return err
				}
			}},
		{rpc: "UserGRPCService.ReissueOneTimePassword", read: "users.read", gate: "users.write", extras: userExtras,
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := newUser(t, h)
				target := svc.mustCreate(t, "readgate-target", "readgate-target@example.com")
				return func(ctx context.Context) error {
					_, err := svc.ReissueOneTimePassword(ctx, &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
					return err
				}
			}},
		{rpc: "UserGRPCService.DeleteUser", read: "users.read", gate: "users.delete", extras: userExtras,
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := newUser(t, h)
				target := svc.mustCreate(t, "readgate-target", "readgate-target@example.com")
				return func(ctx context.Context) error {
					_, err := svc.DeleteUser(ctx, &pb.DeleteUserRequest{Id: target.GetId()})
					return err
				}
			}},
		// system.read for CreateRole/UpdateRole: the new permission set must be
		// one the actor already holds (resolvePermissionIDs' bundling ceiling).
		{rpc: "RoleGRPCService.CreateRole", read: "roles.read", gate: "roles.write", extras: []string{"system.read"},
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewRoleService(h.CoreService)
				return func(ctx context.Context) error {
					_, err := svc.CreateRole(ctx, &pb.CreateRoleRequest{
						Name: "readgate-created", Description: "read-gate family role", Permissions: []string{"system.read"},
					})
					return err
				}
			}},
		{rpc: "RoleGRPCService.UpdateRole", read: "roles.read", gate: "roles.write", extras: []string{"system.read"},
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewRoleService(h.CoreService)
				target := h.CreateTestRole(t, "readgate-target-role", "role to update", 320)
				return func(ctx context.Context) error {
					_, err := svc.UpdateRole(ctx, &pb.UpdateRoleRequest{
						Id: uint32(target.ID), Description: strPtr("updated"), Permissions: []string{"system.read"},
					})
					return err
				}
			}},
		{rpc: "RoleGRPCService.DeleteRole", read: "roles.read", gate: "roles.write",
			setup: func(t *testing.T, h *testhelper.RBACTestHelper) func(context.Context) error {
				svc := NewRoleService(h.CoreService)
				target := h.CreateTestRole(t, "readgate-target-role", "unused role to delete", 320)
				return func(ctx context.Context) error {
					_, err := svc.DeleteRole(ctx, &pb.DeleteRoleRequest{Id: uint32(target.ID)})
					return err
				}
			}},
	}
}

// TestGRPCMutations_RequireReadGate_Family: for every authorizeGlobalMutation
// RPC, the write/delete/assign permission alone is denied and the same
// permission plus the route group's read permission succeeds.
func TestGRPCMutations_RequireReadGate_Family(t *testing.T) {
	for _, c := range readGateFamilyCases() {
		t.Run(c.rpc, func(t *testing.T) {
			h := testhelper.NewRBACTestHelper(t)
			t.Cleanup(h.Cleanup)
			h.AssignUserRole(t, 1, 1, nil) // user 1 = super_admin, for target setup
			grantReadGatePrincipals(t, h, c)
			call := c.setup(t, h)

			// The denied call runs first and must not mutate, so the allowed call
			// below acts on the same untouched target.
			err := call(authCtx(readGateGateOnlyID, "gate-only"))
			require.Error(t, err, "known-01: %s holder without %s must NOT pass %s over gRPC", c.gate, c.read, c.rpc)
			require.Equal(t, codes.PermissionDenied, status.Code(err), "unexpected error: %v", err)

			err = call(authCtx(readGateReadAndGateID, "read-and-gate"))
			require.NoError(t, err, "a holder of %s + %s must still pass %s", c.read, c.gate, c.rpc)
		})
	}
}

// TestGRPCMutations_ReadGateFamily_CoversEveryGatedRPC fails when the table
// above and the methods that call authorizeGlobalMutation drift apart: a gated
// RPC missing from the table, or a table row whose RPC no longer calls it.
func TestGRPCMutations_ReadGateFamily_CoversEveryGatedRPC(t *testing.T) {
	fset := token.NewFileSet()
	var gated []string
	for _, file := range []string{"group_service.go", "user_service.go", "role_service.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			recv, ok := star.X.(*ast.Ident)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "authorizeGlobalMutation" {
						gated = append(gated, recv.Name+"."+fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	slices.Sort(gated)
	gated = slices.Compact(gated)

	var table []string
	for _, c := range readGateFamilyCases() {
		table = append(table, c.rpc)
	}
	slices.Sort(table)

	require.Len(t, gated, 13, "expected the 13 known-01 RPCs to call authorizeGlobalMutation; found %v", gated)
	require.Equal(t, gated, table, "readGateFamilyCases must list exactly the RPCs that call authorizeGlobalMutation")
}
