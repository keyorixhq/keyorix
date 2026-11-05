package authzdiff

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// The operation table. Every op names its matrix row (MATRIX.md core entry),
// the targets it is meaningful for, the reference-model requirement, and one
// function per layer. A nil layer function means the layer has no such op
// (matrix gap) — never that the harness skipped it silently.
//
// Requirement source (the spec Oracle 2 checks against): the REST router gate
// recorded in scripts/e2e/routes.json (no per-op permission is documented in
// OpenAPI), plus the FIX-1 grant ceiling for ops that grant a role. Oracle 2
// against REST is therefore a check of scope resolution, expiry, machine
// no-bypass and the ceiling — not of WHICH permission the route names; it is
// fully independent only for core and gRPC.

// tgt selects the target: 0 = project A, 1 = project B, 2 = global.
type tgt byte

const (
	tA tgt = iota
	tB
	tGlobal
)

func (t tgt) String() string { return [...]string{"A", "B", "global"}[t] }

var projTargets = []tgt{tA, tB}

// errNotAuthzLayer: for this principal the transport would call a core method
// that performs no authorization (e.g. a machine actor's plain core.UpdateSecret
// after the transport's own check). The core leg is recorded as n/a.
var errNotAuthzLayer = errors.New("core leg is not an authorization layer for this principal")

type restReq struct {
	method, path string
	body         any
}

// errItemRefused: a core call returned no error but reported the item refused
// (bulk ops); mapped to Denied with detail "item-refused".
var errItemRefused = errors.New("item refused")

type opSpec struct {
	name    string
	row     string // MATRIX.md core entry
	targets []tgt
	// coreEnforced is NOT hand-set: the runner derives it from matrix.json's
	// core_refusal for row (!= "none"), and fails if the row is missing. False =
	// transport-enforced (intended difference ID-2): the core leg is recorded
	// but excluded from Oracle 1.
	coreEnforced bool
	// selfMachineGranter: the transports tag a machine actor with
	// core.WithSelfMachineGranter before calling core for this op (grep of
	// server/ at bd16d6921: groups_members.go, rbac.go:830, machine_identities.go:600,
	// project_memberships.go:165, group_service.go:177); the core leg mirrors it.
	selfMachineGranter bool
	// secretArgs: the op arg selects the fixture secret (sec): 0 = admin-owned,
	// no share/ACL for any probed principal; 1 = owned by the viewer principal;
	// 2 = shared (write: viewer, read: custom); 3 = ACL (secrets.write: viewer,
	// secrets.read: custom). Shares/ACLs exist in project A only — recipients
	// must be members, and the probed principals are members of A only — so in
	// B args 2/3 are the "off" case. Args 1-3 are OUTSIDE the model's domain
	// (owner/share/ACL semantics beyond the documented owner rules): Oracle 1
	// applies, Oracle 2 is recorded as n/a.
	secretArgs bool
	// grantArgs: the op arg selects the granted role (grantRoles).
	grantArgs bool
	// restOK, when set, decides "allowed" for a REST 2xx from the body (bulk
	// ops answer 200 even when the item was refused). Nil = any 2xx is allowed.
	restOK func(body []byte, fx *fixtures, t tgt) bool
	// controlAs: extra positive-control principals tried after the admin
	// (requester-only ops: no admin can satisfy the rule).
	controlAs []principalKind
	req       func(fx *fixtures, t tgt, a byte) requirement
	core      func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error
	rest      func(fx *fixtures, t tgt, a byte) restReq
	grpc      func(ctx context.Context, lg *leg, t tgt, a byte) error
}

// grantRoles is the fuzzed choice of role an op grants.
var grantRoles = []string{"project_viewer", "release-manager", "project_admin", "editor"}

func grantRole(fx *fixtures, a byte) (string, uint) {
	n := grantRoles[int(a)%len(grantRoles)]
	return n, fx.roleIDs[n]
}

func pid(fx *fixtures, t tgt) uint {
	if t == tGlobal {
		return 0
	}
	return fx.proj(byte(t)).projectID
}

// actorArgs mirrors what the transports pass to core for a principal: a
// machine actor is (userID 0, machineID, isMachine=true) with the machine
// tagged on ctx, exactly as the REST/gRPC auth layers do.
func actorCtx(ctx context.Context, p *principal) context.Context {
	if p.isMachine() {
		ctx = core.WithActorType(ctx, core.ActorTypeMachine)
		ctx = core.WithMachineActor(ctx, p.machineID)
	}
	if p.pat != nil {
		// the transports attach a PAT's restriction to ctx; mirror it
		ctx = core.WithPATRestriction(ctx, p.pat)
	}
	return ctx
}

// ops is every bound operation: the hand-bound Phase 2 set plus the Phase 4
// family bindings. The sweep orders them by family (coverage_test.go).
func ops() []opSpec { return append(baseOps(), familyOps()...) }

func baseOps() []opSpec {
	return []opSpec{
		// ---- REST-vs-gRPC divergent secret operations (MATRIX.md result 3) ----
		{
			name: "secret.update", row: "UpdateSecretWithPermissionCheck", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				_, err := lg.c.UpdateSecretWithPermissionCheck(ctx, &core.UpdateSecretRequest{ID: sec(lg.fx, t, a).id, Value: []byte("synthetic-new"), UpdatedBy: p.username, UserID: p.userID})
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", sec(fx, t, a).id), map[string]any{"value": "synthetic-new"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				v := "synthetic-new"
				_, err := pb.NewSecretServiceClient(lg.conn).UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: uint32(sec(lg.fx, t, a).id), Value: &v})
				return err
			},
		},
		{
			name: "secret.delete", row: "DeleteSecretWithPermissionCheck", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.delete"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				return lg.c.DeleteSecretWithPermissionCheck(ctx, sec(lg.fx, t, a).id, p.userID)
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", sec(fx, t, a).id), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				_, err := pb.NewSecretServiceClient(lg.conn).DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: uint32(sec(lg.fx, t, a).id)})
				return err
			},
		},
		{
			name: "secret.acl.grant", row: "GrantSecretACL", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.manage"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				return lg.c.GrantSecretACL(ctx, p.userID, sec(lg.fx, t, a).id, lg.fx.aclRecipientID, []string{"secrets.read"})
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sec(fx, t, a).id),
					map[string]any{"user_id": fx.aclRecipientID, "permissions": []string{"secrets.read"}}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				_, err := pb.NewSecretServiceClient(lg.conn).GrantSecretACL(ctx, &pb.GrantSecretACLRequest{
					SecretId: uint64(sec(lg.fx, t, a).id), UserId: uint64(lg.fx.aclRecipientID), Permissions: []string{"secrets.read"}})
				return err
			},
		},
		{
			name: "secret.acl.revoke", row: "RevokeSecretACL", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.manage"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				pp := sec(lg.fx, t, a)
				return lg.c.RevokeSecretACL(ctx, p.userID, pp.id, pp.aclID)
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				pp := sec(fx, t, a)
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/%d", pp.id, pp.aclID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				pp := sec(lg.fx, t, a)
				_, err := pb.NewSecretServiceClient(lg.conn).RevokeSecretACL(ctx, &pb.RevokeSecretACLRequest{SecretId: uint64(pp.id), AclId: uint64(pp.aclID)})
				return err
			},
		},
		{
			name: "secret.autorotate", row: "SetSecretAutoRotate", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				actor := p.userID
				if p.isMachine() {
					actor = p.machineID
				}
				return lg.c.SetSecretAutoRotate(ctx, sec(lg.fx, t, a).id, core.AutoRotateSpec{Enabled: true}, actor)
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/auto-rotate", sec(fx, t, a).id), map[string]any{"enabled": true}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				_, err := pb.NewSecretServiceClient(lg.conn).SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{Id: uint32(sec(lg.fx, t, a).id), Enabled: true})
				return err
			},
		},
		{
			name: "secret.share", row: "ShareSecret", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t), ownerUserID: fx.adminID}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, err := lg.c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: sec(lg.fx, t, a).id, RecipientID: lg.fx.targetUserID, Permission: "read", SharedBy: p.userID})
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", sec(fx, t, a).id),
					map[string]any{"recipient_id": fx.targetUserID, "permission": "read"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				_, err := pb.NewShareServiceClient(lg.conn).ShareSecret(ctx, &pb.ShareSecretRequest{SecretId: uint32(sec(lg.fx, t, a).id), RecipientId: uint32(lg.fx.targetUserID), Permission: "read"})
				return err
			},
		},
		valueRead("secret.value.byref", func(fx *fixtures, t tgt, a byte) string {
			return "/api/v1/secrets/value?ref=" + sec(fx, t, a).ref
		}),
		valueRead("secret.value.byid", func(fx *fixtures, t tgt, a byte) string {
			return fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sec(fx, t, a).id)
		}),

		// ---- groups ----
		{
			name: "group.create", row: "CreateGroup", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"users.read", "users.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, err := lg.c.CreateGroup(ctx, p.userID, &core.CreateGroupRequest{Name: "gnew"})
				return err
			},
			rest: func(*fixtures, tgt, byte) restReq {
				return restReq{http.MethodPost, "/api/v1/groups", map[string]any{"name": "gnew"}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewGroupServiceClient(lg.conn).CreateGroup(ctx, &pb.CreateGroupRequest{Name: "gnew"})
				return err
			},
		},
		{
			name: "group.update", row: "UpdateGroup", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"users.read", "users.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, err := lg.c.UpdateGroup(ctx, p.userID, &core.UpdateGroupRequest{ID: lg.fx.groupID, Name: "gupd"})
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/groups/%d", fx.groupID), map[string]any{"name": "gupd"}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewGroupServiceClient(lg.conn).UpdateGroup(ctx, &pb.UpdateGroupRequest{Id: uint32(lg.fx.groupID), Name: "gupd"})
				return err
			},
		},
		{
			name: "group.delete", row: "DeleteGroup", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"users.read", "users.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.DeleteGroup(ctx, p.userID, lg.fx.groupID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d", fx.groupID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewGroupServiceClient(lg.conn).DeleteGroup(ctx, &pb.DeleteGroupRequest{Id: uint32(lg.fx.groupID)})
				return err
			},
		},
		{
			// joining the group grants its role (project_auditor@A): FIX-1 ceiling.
			// The membership's own project (target) is only expressible on REST;
			// gRPC is always a global membership, so its leg runs for tGlobal only.
			name: "group.member.add", row: "AddUserToGroup", targets: []tgt{tGlobal, tA, tB}, selfMachineGranter: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign", "users.read"}, ceiling: []roleAt{{fx.roleIDs["project_auditor"], fx.A.projectID}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.AddUserToGroup(ctx, p.userID, p.isMachine(), lg.fx.principals[pkNone].userID, lg.fx.groupID, pid(lg.fx, t))
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", fx.groupID),
					map[string]any{"user_id": fx.principals[pkNone].userID, "project_id": pid(fx, t)}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				if t != tGlobal {
					return errLayerAbsent
				}
				_, err := pb.NewGroupServiceClient(lg.conn).AddGroupMember(ctx, &pb.GroupMemberRequest{GroupId: uint32(lg.fx.groupID), UserId: uint32(lg.fx.principals[pkNone].userID)})
				return err
			},
		},
		{
			name: "group.member.remove", row: "RemoveUserFromGroup", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.assign", "users.read"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.RemoveUserFromGroup(ctx, p.userID, lg.fx.targetUserID, lg.fx.groupID, 0)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d/members/%d", fx.groupID, fx.targetUserID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewGroupServiceClient(lg.conn).RemoveGroupMember(ctx, &pb.GroupMemberRequest{GroupId: uint32(lg.fx.groupID), UserId: uint32(lg.fx.targetUserID)})
				return err
			},
		},
		{
			// target = the SCOPE the role is granted at; the route gate is global roles.assign.
			name: "group.role.assign", row: "AssignRoleToGroup", targets: []tgt{tA, tB, tGlobal}, grantArgs: true, selfMachineGranter: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign", "users.read"}, ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, rid := grantRole(lg.fx, a)
				return lg.c.AssignRoleToGroup(ctx, p.userID, lg.fx.groupID, rid, core.Scope{ProjectID: pid(lg.fx, t)}, p.isMachine())
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				_, rid := grantRole(fx, a)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/roles", fx.groupID), map[string]any{"role_id": rid, "project_id": pid(fx, t)}}
			},
		},
		{
			name: "group.role.remove", row: "RemoveRoleFromGroup", targets: []tgt{tA},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.assign", "users.read"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.RemoveRoleFromGroup(ctx, p.userID, lg.fx.groupID, lg.fx.roleIDs["project_auditor"], core.Scope{ProjectID: lg.fx.A.projectID})
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d/roles/%d?project_id=%d", fx.groupID, fx.roleIDs["project_auditor"], fx.A.projectID), nil}
			},
		},

		// ---- projects (core takes no actor for create/update: no core leg) ----
		{
			name: "project.create", row: "CreateProject", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement { return requirement{perms: []string{"secrets.write"}} },
			rest: func(*fixtures, tgt, byte) restReq {
				return restReq{http.MethodPost, "/api/v1/projects", map[string]any{"name": "pnew"}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewProjectServiceClient(lg.conn).CreateProject(ctx, &pb.CreateProjectRequest{Name: "pnew"})
				return err
			},
		},
		{
			name: "project.update", row: "UpdateProject", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t)}
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/projects/%d", pid(fx, t)), map[string]any{"name": "prenamed"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				_, err := pb.NewProjectServiceClient(lg.conn).UpdateProject(ctx, &pb.UpdateProjectRequest{Id: uint32(pid(lg.fx, t)), Name: "prenamed"})
				return err
			},
		},
		{
			name: "project.delete", row: "DeleteProject", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.delete"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.DeleteProject(ctx, p.userID, pid(lg.fx, t), true)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d?force=true", pid(fx, t)), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				_, err := pb.NewProjectServiceClient(lg.conn).DeleteProject(ctx, &pb.DeleteProjectRequest{Id: uint32(pid(lg.fx, t)), Force: true})
				return err
			},
		},

		// ---- machine identities ----
		{
			name: "machine.create", row: "CreateMachineIdentity", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.CreateMachineIdentity(ctx, pid(lg.fx, t), "mnew", "service", "", "", p.userID, p.machineID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities", pid(fx, t)), map[string]any{"name": "mnew"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				_, err := pb.NewMachineIdentityServiceClient(lg.conn).CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{ProjectId: uint32(pid(lg.fx, t)), Name: "mnew"})
				return err
			},
		},
		{
			name: "machine.token.issue", row: "IssueMachineToken", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.IssueMachineToken(ctx, pp.projectID, pp.machineID, p.userID, core.IssueMachineTokenParams{Name: "t2"})
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", pp.projectID, pp.machineID), map[string]any{"name": "t2"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewMachineIdentityServiceClient(lg.conn).IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{ProjectId: uint32(pp.projectID), MachineId: uint32(pp.machineID), Name: "t2"})
				return err
			},
		},
		{
			name: "machine.token.revoke", row: "RevokeMachineToken", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.RevokeMachineToken(ctx, pp.projectID, pp.machineID, pp.machineCredID, p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens/%d", pp.projectID, pp.machineID, pp.machineCredID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewMachineIdentityServiceClient(lg.conn).RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{ProjectId: uint32(pp.projectID), MachineId: uint32(pp.machineID), TokenId: uint32(pp.machineCredID)})
				return err
			},
		},
		{
			name: "machine.transition", row: "TransitionMachineIdentity", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.TransitionMachineIdentity(ctx, pp.projectID, pp.machineID, "suspended", p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d", pp.projectID, pp.machineID), map[string]any{"action": "suspend"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewMachineIdentityServiceClient(lg.conn).TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{ProjectId: uint32(pp.projectID), MachineId: uint32(pp.machineID), Action: "suspend"})
				return err
			},
		},
		{
			name: "machine.role.assign", row: "AssignMachineRole", targets: projTargets, grantArgs: true, selfMachineGranter: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, rid := grantRole(lg.fx, a)
				pp := lg.fx.proj(byte(t))
				return lg.c.AssignMachineRole(ctx, pp.machineID, rid, core.Scope{ProjectID: pp.projectID}, p.userID, p.isMachine())
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				_, rid := grantRole(fx, a)
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/roles", pp.projectID, pp.machineID), map[string]any{"role_id": rid}}
			},
		},

		// ---- invitations ----
		{
			name: "invitation.create", row: "InviteToProjectWithLink", targets: projTargets, grantArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				_, _, err := lg.c.InviteToProjectWithLink(ctx, pid(lg.fx, t), "new-invitee@example.invalid", rn, p.userID, p.machineID)
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				rn, _ := grantRole(fx, a)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/invitations", pid(fx, t)), map[string]any{"email": "new-invitee@example.invalid", "role": rn}}
			},
		},
		{
			name: "invitation.revoke", row: "RevokeInvitation", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.RevokeInvitation(ctx, pp.projectID, pp.invitationID, p.userID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d/invitations/%d", pp.projectID, pp.invitationID), nil}
			},
		},

		// ---- access requests ----
		{
			name: "accessrequest.approve", row: "ApproveAccessRequestWithExpiry", targets: projTargets, grantArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.ApproveAccessRequestWithExpiry(ctx, pp.projectID, pp.accessRequestID, p.userID, p.machineID, rn, 0)
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				rn, _ := grantRole(fx, a)
				pp := fx.proj(byte(t))
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/access-requests/%d", pp.projectID, pp.accessRequestID), map[string]any{"action": "approve", "granted_role": rn}}
			},
		},
		{
			name: "accessrequest.reject", row: "RejectAccessRequest", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.RejectAccessRequest(ctx, pp.projectID, pp.accessRequestID, p.userID, p.machineID, "synthetic")
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/access-requests/%d", pp.projectID, pp.accessRequestID), map[string]any{"action": "reject", "reason": "synthetic"}}
			},
		},

		// ---- memberships ----
		{
			// invited -> identity_verified: not a role-granting step, so no ceiling.
			name: "membership.transition", row: "TransitionMembership", targets: projTargets, selfMachineGranter: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.TransitionMembership(ctx, pp.projectID, pp.membershipID, "identity_verified", p.userID, p.isMachine())
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/memberships/%d", pp.projectID, pp.membershipID), map[string]any{"action": "verify"}}
			},
		},
	}
}

// sec returns the fixture secret op arg a selects in target t (see secretArgs).
func sec(fx *fixtures, t tgt, a byte) fixtureSecret {
	return fx.proj(byte(t)).secrets[int(a)%len(fx.proj(byte(t)).secrets)]
}

// errLayerAbsent: this layer has no equivalent call for this target.
var errLayerAbsent = errors.New("layer has no such call for this target")

// valueRead builds a secret-value read op; the REST path differs per variant,
// the core and gRPC legs are shared. Values are discarded, never printed.
func valueRead(name string, path func(*fixtures, tgt, byte) string) opSpec {
	return opSpec{
		name: name, row: "GetSecretForValueRead", targets: projTargets, secretArgs: true,
		req: func(fx *fixtures, t tgt, a byte) requirement {
			return requirement{perms: []string{"secrets.read"}, scope: pid(fx, t)}
		},
		core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
			if p.isMachine() {
				return errNotAuthzLayer
			}
			ps, err := lg.c.GetSecretForValueRead(ctx, sec(lg.fx, t, a).id, p.userID)
			if err != nil {
				return err
			}
			_, err = lg.c.GetPermittedSecretValue(ctx, ps)
			return err
		},
		rest: func(fx *fixtures, t tgt, a byte) restReq { return restReq{http.MethodGet, path(fx, t, a), nil} },
		grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
			_, err := pb.NewSecretServiceClient(lg.conn).GetSecretValue(ctx, &pb.GetSecretRequest{Id: uint32(sec(lg.fx, t, a).id), IncludeValue: true})
			return err
		},
	}
}
