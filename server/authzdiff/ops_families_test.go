package authzdiff

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// familyOps are the Phase 4 bindings, in the families order of the review
// (groups, projects, machine identities, invitations, access requests,
// memberships). Which routes exist and which are in scope is NOT decided here:
// coverage_test.go derives the family route population from matrix.json and
// matches each op's actual REST request against it. These functions only bind
// a route to fixture arguments and to the core/gRPC calls behind it.
func familyOps() []opSpec {
	return []opSpec{
		// ---- groups ----
		{
			name: "group.restore", row: "RestoreGroup", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"users.read", "roles.assign"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, err := lg.c.RestoreGroup(ctx, p.userID, lg.fx.deletedGroupID)
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/restore", fx.deletedGroupID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewGroupServiceClient(lg.conn).RestoreGroup(ctx, &pb.RestoreGroupRequest{Id: uint32(lg.fx.deletedGroupID)})
				return err
			},
		},

		// ---- projects ----
		{
			// the soft-deleted project C: grants scoped to it do not apply (the
			// project is not live), so only global grants can satisfy the gate.
			name: "project.restore", row: "RestoreProject", targets: []tgt{tA},
			req: func(fx *fixtures, _ tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: fx.projCID}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.RestoreProject(ctx, p.userID, lg.fx.projCID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/restore", fx.projCID), nil}
			},
		},
		{
			// core.CreateEnvironment takes no actor: no core leg.
			name: "env.create", row: "CreateEnvironment", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t)}
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments", pid(fx, t)), map[string]any{"name": "qa"}}
			},
		},
		{
			name: "env.restore", row: "RestoreEnvironment", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				// documented: restoring reinstates the project's role assignments, and
				// when any is an admin role the actor must be a global admin
				// (requireAuthorityToReinstateProjectRoles). Projects A and B hold
				// project_admin assignments, so the rule always applies here.
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalAdminRole: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.RestoreEnvironment(ctx, p.userID, pp.projectID, pp.deletedEnvID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments/%d/restore", pp.projectID, pp.deletedEnvID), nil}
			},
		},

		// ---- machine identities ----
		{
			name: "machine.classify", row: "ClassifyMachineIdentity", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.ClassifyMachineIdentity(ctx, pp.projectID, pp.machineID, "confidential", p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/classification", pp.projectID, pp.machineID), map[string]any{"classification": "confidential"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewMachineIdentityServiceClient(lg.conn).ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{ProjectId: uint32(pp.projectID), MachineId: uint32(pp.machineID), Classification: "confidential"})
				return err
			},
		},
		{
			name: "machine.token.classify", row: "ClassifyMachineToken", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.ClassifyMachineToken(ctx, pp.projectID, pp.machineID, pp.machineCredID, "confidential", p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens/%d/classification", pp.projectID, pp.machineID, pp.machineCredID), map[string]any{"classification": "confidential"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewMachineIdentityServiceClient(lg.conn).ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{ProjectId: uint32(pp.projectID), MachineId: uint32(pp.machineID), TokenId: uint32(pp.machineCredID), Classification: "confidential"})
				return err
			},
		},
		{
			name: "machine.role.remove", row: "RemoveMachineRole", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.RemoveMachineRole(ctx, pp.machineID, pp.machineRoleID, core.Scope{ProjectID: pp.projectID}, p.userID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/roles/%d", pp.projectID, pp.machineID, pp.machineRoleID), nil}
			},
		},
		{
			name: "machine.oidc.create", row: "CreateOIDCBinding", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalAdminRole: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.CreateOIDCBinding(ctx, pp.projectID, pp.machineID, "https://issuer.example.invalid", "subject-new", p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings", pp.projectID, pp.machineID), map[string]any{"issuer": "https://issuer.example.invalid", "subject": "subject-new"}}
			},
		},
		{
			name: "machine.oidc.delete", row: "DeleteOIDCBinding", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.DeleteOIDCBinding(ctx, pp.projectID, pp.machineID, pp.oidcBindingID, p.userID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings/%d", pp.projectID, pp.machineID, pp.oidcBindingID), nil}
			},
		},
		{
			// gated at two scopes: roles.assign@project, then users.write@global.
			name: "machine.migrate", row: "MigrateUserToMachine", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalPerms: []string{"users.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.MigrateUserToMachine(ctx, pp.migrateUsername, pp.projectID, "service", "", p.userID, p.machineID, false)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities/migrate-from-user", pp.projectID), map[string]any{"username": pp.migrateUsername, "keep_user": true}}
			},
		},

		// ---- invitations ----
		{
			// no system role in the body: core defaults to system_viewer, whose
			// permissions are the grant ceiling (at global scope).
			name: "invitation.global", row: "InviteGlobalWithLink", targets: []tgt{tGlobal},
			req: func(fx *fixtures, _ tgt, _ byte) requirement {
				return requirement{perms: []string{"users.write"}, ceiling: []roleAt{{fx.roleIDs["system_viewer"], 0}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, _, err := lg.c.InviteGlobalWithLink(ctx, "global-invitee@example.invalid", "", nil, p.userID, p.machineID)
				return err
			},
			rest: func(*fixtures, tgt, byte) restReq {
				return restReq{http.MethodPost, "/api/v1/invitations", map[string]any{"email": "global-invitee@example.invalid"}}
			},
		},
		{
			name: "invitation.resend", row: "ResendInvitationLink", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.ResendInvitationLink(ctx, pp.projectID, pp.invitationID, p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/invitations/%d/resend", pp.projectID, pp.invitationID), nil}
			},
		},

		// ---- access requests ----
		{
			// no gate beyond authentication: any live user may ask for access.
			name: "accessrequest.create", row: "RequestProjectAccess", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement { return requirement{scope: pid(fx, t)} },
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.RequestProjectAccess(ctx, pid(lg.fx, t), p.userID, "project_viewer", "synthetic")
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/access-requests", pid(fx, t)), map[string]any{"suggested_role": "project_viewer", "reason": "synthetic"}}
			},
		},
		{
			// requester-only: no probed principal is the requester, so the
			// positive control is the requester itself.
			name: "accessrequest.withdraw", row: "WithdrawAccessRequest", targets: []tgt{tA}, controlAs: []principalKind{pkRequester},
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{scope: pid(fx, t), requesterUserID: fx.requesterIDs[0]}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.WithdrawAccessRequest(ctx, lg.fx.A.accessRequestID, p.userID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/access-requests/%d/withdraw", fx.A.projectID, fx.A.accessRequestID), nil}
			},
		},
		{
			// global roles.assign gate, then per-item roles.assign at the request's
			// project, then the approval ceiling (the suggested project_viewer).
			// 200 with a per-item failure is "denied" (restOK / errItemRefused).
			name: "accessrequest.bulk.approve", row: "BulkApproveAccessRequests", targets: projTargets,
			restOK: func(b []byte, fx *fixtures, t tgt) bool {
				return jsonListHas(b, "approved", fx.proj(byte(t)).accessRequestID)
			},
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalPerms: []string{"roles.assign"},
					ceiling: []roleAt{{fx.roleIDs["project_viewer"], pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				id := lg.fx.proj(byte(t)).accessRequestID
				res, err := lg.c.BulkApproveAccessRequests(ctx, []uint{id}, p.userID, p.machineID)
				if err != nil {
					return err
				}
				if !slices.Contains(res.Approved, id) {
					return errItemRefused
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, "/api/v1/access-requests/bulk-approve", map[string]any{"request_ids": []uint{fx.proj(byte(t)).accessRequestID}}}
			},
		},
		{
			name: "accessrequest.bulk.reject", row: "BulkRejectAccessRequests", targets: projTargets,
			restOK: func(b []byte, fx *fixtures, t tgt) bool {
				return jsonListHas(b, "rejected", fx.proj(byte(t)).accessRequestID)
			},
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalPerms: []string{"roles.assign"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				id := lg.fx.proj(byte(t)).accessRequestID
				res, err := lg.c.BulkRejectAccessRequests(ctx, []uint{id}, p.userID, p.machineID, "synthetic")
				if err != nil {
					return err
				}
				if !slices.Contains(res.Rejected, id) {
					return errItemRefused
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, "/api/v1/access-requests/bulk-reject", map[string]any{"request_ids": []uint{fx.proj(byte(t)).accessRequestID}, "reason": "synthetic"}}
			},
		},

		// ---- memberships ----
		{
			name: "membership.invite", row: "InviteMember", targets: projTargets, grantArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				_, err := lg.c.InviteMember(ctx, pid(lg.fx, t), lg.fx.freshUserID, rn, p.userID, p.machineID, false)
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				rn, _ := grantRole(fx, a)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/memberships", pid(fx, t)), map[string]any{"user_id": fx.freshUserID, "role": rn}}
			},
		},
		{
			name: "member.add", row: "AddProjectMember", targets: projTargets, grantArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				return lg.c.AddProjectMember(ctx, p.userID, pid(lg.fx, t), lg.fx.freshUserID2, rn, p.isMachine())
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				rn, _ := grantRole(fx, a)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/members", pid(fx, t)), map[string]any{"user_id": fx.freshUserID2, "role": rn}}
			},
		},
		{
			// the ACL recipient holds project_viewer@P; arg 0 re-sets the same role (no-op).
			name: "member.setrole", row: "SetProjectMemberRole", targets: projTargets, grantArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				rn, rid := grantRole(fx, a)
				if rn == "project_viewer" {
					// documented no-op: the member already holds exactly this role
					// (SetProjectMemberRole: audited only), so nothing is granted.
					return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
				}
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				return lg.c.SetProjectMemberRole(ctx, p.userID, pid(lg.fx, t), lg.fx.aclRecipientID, rn, p.isMachine())
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				rn, _ := grantRole(fx, a)
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/members/%d", pid(fx, t), fx.aclRecipientID), map[string]any{"role": rn}}
			},
		},
		{
			name: "member.remove", row: "RemoveProjectMember", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.RemoveProjectMember(ctx, p.userID, pid(lg.fx, t), lg.fx.aclRecipientID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d/members/%d", pid(fx, t), fx.aclRecipientID), nil}
			},
		},
	}
}

// jsonListHas reports whether the JSON body contains, anywhere, an array under
// key that includes id (bulk results: {"approved":[...]} / {"rejected":[...]},
// at whatever envelope depth the handler wraps them).
func jsonListHas(body []byte, key string, id uint) bool {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(n any) bool {
		switch x := n.(type) {
		case map[string]any:
			if arr, ok := x[key].([]any); ok {
				for _, e := range arr {
					if f, ok := e.(float64); ok && uint(f) == id {
						return true
					}
				}
			}
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		case []any:
			return slices.ContainsFunc(x, walk)
		}
		return false
	}
	return walk(v)
}
