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

// phase5Ops are the Phase 5 bindings: the remaining secret operations (on the
// secretFixtures), then the users/roles operations (on the userFixtures).
//
// Each core leg passes the same actor arguments the handler passes, so it
// reproduces what core sees through REST.
func phase5Ops() []opSpec { return append(secretPhase5Ops(), userPhase5Ops()...) }

func sxOf(fx *fixtures, t tgt) *secretFixtures { return &fx.proj(byte(t)).sx }

// principalActor is what a handler passes as (ActorKind(), PrincipalID()).
func principalActor(p *principal) (string, uint) {
	if p.isMachine() {
		return core.ActorTypeMachine, p.machineID
	}
	return core.ActorTypeUser, p.userID
}

func atP(perm string) func(fx *fixtures, t tgt, _ byte) requirement {
	return func(fx *fixtures, t tgt, _ byte) requirement {
		return requirement{perms: []string{perm}, scope: pid(fx, t)}
	}
}

func secretPhase5Ops() []opSpec {
	return []opSpec{
		{
			// gated by the handler (AuthorizePrincipal secrets.write at the body's
			// scope).
			name: "secret.create", row: "CreateSecret", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.CreateSecret(ctx, &core.CreateSecretRequest{Name: "created", Value: []byte("synthetic-created"),
					ProjectID: pp.projectID, EnvironmentID: pp.envID, Type: "password", CreatedBy: p.username, OwnerID: p.userID})
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, "/api/v1/secrets", map[string]any{"name": "created", "value": "synthetic-created",
					"project_id": pp.projectID, "environment_id": pp.envID, "type": "password"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewSecretServiceClient(lg.conn).CreateSecret(ctx, &pb.CreateSecretRequest{Name: "created", Value: "synthetic-created",
					ProjectId: uint32(pp.projectID), EnvironmentId: uint32(pp.envID), Type: "password"})
				return err
			},
		},
		{
			name: "secret.description", row: "SetSecretDescription", targets: projTargets, secretArgs: true,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, err := lg.c.SetSecretDescription(ctx, p.userID, sec(lg.fx, t, a).id, "synthetic")
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/description", sec(fx, t, a).id), map[string]any{"description": "synthetic"}}
			},
		},
		{
			name: "secret.tags", row: "SetSecretTags", targets: projTargets, secretArgs: true,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, err := lg.c.SetSecretTags(ctx, sec(lg.fx, t, a).id, p.userID, []string{"synthetic"})
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/tags", sec(fx, t, a).id), map[string]any{"tags": []string{"synthetic"}}}
			},
		},
		{
			name: "secret.retention", row: "SetSecretRetentionOverride", targets: projTargets,
			req: atP("secrets.manage"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.SetSecretRetentionOverride(ctx, p.userID, sxOf(lg.fx, t).plainID, 30)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/retention", sxOf(fx, t).plainID), map[string]any{"retention_override_days": 30}}
			},
		},
		{
			// owner-only (requireShareAuthority) behind a secrets.write gate.
			name: "share.revoke", row: "RevokeShare", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t), ownerUserID: fx.adminID}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.RevokeShare(ctx, sxOf(lg.fx, t).shareID, p.userID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", sxOf(fx, t).shareID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				_, err := pb.NewShareServiceClient(lg.conn).RevokeShare(ctx, &pb.RevokeShareRequest{ShareId: uint32(sxOf(lg.fx, t).shareID)})
				return err
			},
		},
		{
			name: "share.update", row: "UpdateSharePermission", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t), ownerUserID: fx.adminID}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.UpdateSharePermission(ctx, &core.UpdateShareRequest{ShareID: sxOf(lg.fx, t).shareID, Permission: "write", UpdatedBy: p.userID})
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/shares/%d", sxOf(fx, t).shareID), map[string]any{"permission": "write"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				_, err := pb.NewShareServiceClient(lg.conn).UpdateSharePermission(ctx, &pb.UpdateSharePermissionRequest{ShareId: uint32(sxOf(lg.fx, t).shareID), Permission: "write"})
				return err
			},
		},
		{
			// s2 in A carries direct shares to the viewer (write) and the custom
			// user (read): only those two may remove themselves. No permission.
			name: "share.self.remove", row: "RemoveSelfFromShare", targets: []tgt{tA}, controlAs: []principalKind{pkViewer},
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{scope: pid(fx, t), recipientUserIDs: []uint{fx.principals[pkViewer].userID, fx.principals[pkCustom].userID}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.RemoveSelfFromShare(ctx, lg.fx.A.secrets[2].id, p.userID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/self-share", fx.A.secrets[2].id), nil}
			},
		},
		{
			// "expiring" comes to depend on "cert" (same project and env).
			name: "secret.dep.add", row: "AddSecretDependency", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				kind, id := principalActor(p)
				s := sxOf(lg.fx, t)
				_, err := lg.c.AddSecretDependency(ctx, kind, id, s.expiringID, s.certID, "synthetic", p.machineID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				s := sxOf(fx, t)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/dependencies", s.expiringID), map[string]any{"depends_on_id": s.certID, "note": "synthetic"}}
			},
		},
		{
			name: "secret.dep.remove", row: "RemoveSecretDependency", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				kind, id := principalActor(p)
				s := sxOf(lg.fx, t)
				return lg.c.RemoveSecretDependency(ctx, kind, id, s.certID, s.depEdgeID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				s := sxOf(fx, t)
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/dependencies/%d", s.certID, s.depEdgeID), nil}
			},
		},
		{
			name: "secret.comment.add", row: "CreateSecretVersionComment", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				s := sxOf(lg.fx, t)
				_, err := lg.c.CreateSecretVersionComment(ctx, core.CreateVersionCommentRequest{SecretID: s.multiVerID, VersionID: s.v1ID, Comment: "synthetic", UserID: p.userID, Username: p.username})
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				s := sxOf(fx, t)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments", s.multiVerID, s.v1ID), map[string]any{"comment": "synthetic"}}
			},
		},
		{
			name: "secret.comment.delete", row: "DeleteSecretVersionComment", targets: projTargets,
			req: atP("secrets.manage"),
			core: func(ctx context.Context, lg *leg, _ *principal, t tgt, _ byte) error {
				s := sxOf(lg.fx, t)
				return lg.c.DeleteSecretVersionComment(ctx, s.multiVerID, s.v1ID, s.commentID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				s := sxOf(fx, t)
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments/%d", s.multiVerID, s.v1ID, s.commentID), nil}
			},
		},
		{
			name: "secret.certificate", row: "InspectCertificate", targets: projTargets,
			req: atP("secrets.read"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.InspectCertificate(ctx, p.userID, sxOf(lg.fx, t).certID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/certificate", sxOf(fx, t).certID), nil}
			},
		},
		{
			name: "secret.restore", row: "RestoreSecret", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.RestoreSecret(ctx, p.userID, sxOf(lg.fx, t).deletedID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/restore", sxOf(fx, t).deletedID), nil}
			},
		},
		{
			name: "secret.suspend", row: "SuspendSecretWithOptions", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.SuspendSecretWithOptions(ctx, sxOf(lg.fx, t).plainID, p.userID, "synthetic", core.SuspendOptions{})
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/suspend", sxOf(fx, t).plainID), map[string]any{"reason": "synthetic"}}
			},
		},
		{
			name: "secret.resume", row: "ResumeSecret", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.ResumeSecret(ctx, sxOf(lg.fx, t).suspendedID, p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/resume", sxOf(fx, t).suspendedID), nil}
			},
		},
		{
			name: "secret.rollback", row: "RollbackSecret", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.RollbackSecret(ctx, sxOf(lg.fx, t).multiVerID, 1, p.userID, p.username)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rollback", sxOf(fx, t).multiVerID), map[string]any{"version": 1}}
			},
		},
		{
			name: "secret.rotate", row: "RotateSecretOnDemand", targets: projTargets,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.RotateSecretOnDemand(ctx, sxOf(lg.fx, t).plainID, []byte("synthetic-rotated"), p.userID, p.username)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", sxOf(fx, t).plainID), map[string]any{"new_value": "synthetic-rotated"}}
			},
		},
		{
			name: "secret.rotation.simulate", row: "SimulateRotation", targets: projTargets,
			req: atP("secrets.read"),
			core: func(ctx context.Context, lg *leg, _ *principal, t tgt, _ byte) error {
				_, err := lg.c.SimulateRotation(ctx, core.RotationDryRunRequest{SecretID: sxOf(lg.fx, t).plainID})
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotation/simulate", sxOf(fx, t).plainID), nil}
			},
		},
		{
			// read on the source (route gate + core), write on the target env
			// (handler); both environments are in the same project.
			name: "secret.copy", row: "CopySecret", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.read", "secrets.write"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				s := sxOf(lg.fx, t)
				_, err := lg.c.CopySecret(ctx, s.plainID, s.targetEnvID, "plain-copy", p.username, p.userID, "", "")
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				s := sxOf(fx, t)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/copy", s.plainID), map[string]any{"environment_id": s.targetEnvID, "name": "plain-copy"}}
			},
		},
		{
			name: "secret.move", row: "MoveSecret", targets: projTargets, secretArgs: true,
			req: atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				f := sxOf(lg.fx, t).folderID
				_, err := lg.c.MoveSecret(ctx, p.userID, sec(lg.fx, t, a).id, &f)
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/move", sec(fx, t, a).id), map[string]any{"parent_id": sxOf(fx, t).folderID}}
			},
		},
		{
			// 200 with extended == 0 is "denied" (restOK / errItemRefused).
			name: "secret.extend.expiring", row: "ExtendExpiringSecrets", targets: projTargets,
			restOK: func(b []byte, _ *fixtures, _ tgt) bool { return jsonNumberPositive(b, "extended") },
			req:    atP("secrets.write"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				n, _, err := lg.c.ExtendExpiringSecrets(ctx, pid(lg.fx, t), 30, 60, p.username, p.userID)
				if err != nil {
					return err
				}
				if n == 0 {
					return errItemRefused
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/secrets/extend-expiring", pid(fx, t)), map[string]any{"within_days": 30, "new_window_days": 60}}
			},
		},
		{
			// copies every prod secret into staging2.
			name: "env.clone", row: "CloneEnvironment", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.write", "secrets.read"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.CloneEnvironment(ctx, pp.projectID, pp.envID, pp.sx.targetEnvID, p.username, p.userID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments/%d/clone", pp.projectID, pp.envID), map[string]any{"destination_environment_id": pp.sx.targetEnvID}}
			},
		},
		{
			name: "env.copy.secrets", row: "CopyEnvironmentSecrets", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.write", "secrets.read"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, _, err := lg.c.CopyEnvironmentSecrets(ctx, pp.projectID, pp.envID, pp.sx.targetEnvID, p.username, p.userID, "", "")
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments/%d/copy-secrets", pp.projectID, pp.envID), map[string]any{"target_environment_id": pp.sx.targetEnvID}}
			},
		},
	}
}

// userCeiling is the rank ceiling for acting on u-acct / u-deleted: each holds
// only the CreateUser baseline, system_viewer at global scope, so the actor
// must hold every system_viewer permission globally (requireEqualOrGreaterAdminAuthority).
func userCeiling(fx *fixtures) []roleAt { return []roleAt{{fx.roleIDs["system_viewer"], 0}} }

// userOp builds a /users/{id}/<verb> account op: users.read (route group) +
// perm, global, with the rank ceiling on the target.
func userOp(name, row, perm, method, suffix string, target func(*fixtures) uint, coreFn func(ctx context.Context, lg *leg, p *principal) error) opSpec {
	return opSpec{
		name: name, row: row, targets: []tgt{tGlobal}, globalHandler: true,
		req: func(fx *fixtures, _ tgt, _ byte) requirement {
			return requirement{perms: []string{"users.read", perm}, ceiling: userCeiling(fx)}
		},
		core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error { return coreFn(ctx, lg, p) },
		rest: func(fx *fixtures, _ tgt, _ byte) restReq {
			return restReq{method, fmt.Sprintf("/api/v1/users/%d%s", target(fx), suffix), nil}
		},
	}
}

func acct(fx *fixtures) uint { return fx.ux.acctUserID }

func userPhase5Ops() []opSpec {
	ops := []opSpec{
		{
			// no role/assignments: CreateUserAudited.
			name: "user.create", row: "CreateUserAudited", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(*fixtures, tgt, byte) requirement { return requirement{perms: []string{"users.read", "users.write"}} },
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, err := lg.c.CreateUserAudited(ctx, &core.CreateUserRequest{Username: "u-new", Email: "u-new@example.invalid", DisplayName: "u-new", Password: fxPassword}, p.userID)
				return err
			},
			rest: func(*fixtures, tgt, byte) restReq {
				return restReq{http.MethodPost, "/api/v1/users", map[string]any{"username": "u-new", "email": "u-new@example.invalid", "display_name": "u-new", "password": fxPassword}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				pw, dn := fxPassword, "u-new"
				_, err := pb.NewUserServiceClient(lg.conn).CreateUser(ctx, &pb.CreateUserRequest{Username: "u-new", Email: "u-new@example.invalid", Password: &pw, DisplayName: &dn})
				return err
			},
		},
		{
			// with a project assignment: roles.assign@P pre-check in the handler,
			// then the granter ceilings for the assigned role and for the default
			// system_viewer (CreateUserWithAssignments).
			name: "user.create.assign", row: "CreateUserWithAssignments", targets: projTargets, grantArgs: true, globalHandler: true, selfMachineGranter: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalPerms: []string{"users.read", "users.write"},
					ceiling: []roleAt{{rid, pid(fx, t)}, {fx.roleIDs["system_viewer"], 0}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				_, err := lg.c.CreateUserWithAssignments(ctx, &core.CreateUserRequest{Username: "u-new", Email: "u-new@example.invalid", DisplayName: "u-new", Password: fxPassword},
					"", []core.ProjectAssignment{{ProjectID: pid(lg.fx, t), Role: rn}}, p.userID, p.isMachine())
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				rn, _ := grantRole(fx, a)
				return restReq{http.MethodPost, "/api/v1/users", map[string]any{"username": "u-new", "email": "u-new@example.invalid", "display_name": "u-new", "password": fxPassword,
					"project_assignments": []map[string]any{{"project_id": pid(fx, t), "role": rn}}}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				rn, _ := grantRole(lg.fx, a)
				pw, dn := fxPassword, "u-new"
				_, err := pb.NewUserServiceClient(lg.conn).CreateUser(ctx, &pb.CreateUserRequest{Username: "u-new", Email: "u-new@example.invalid", Password: &pw, DisplayName: &dn,
					ProjectAssignments: []*pb.ProjectAssignment{{ProjectId: uint32(pid(lg.fx, t)), Role: rn}}})
				return err
			},
		},
		{
			name: "user.update", row: "UpdateUser", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(fx *fixtures, _ tgt, _ byte) requirement {
				return requirement{perms: []string{"users.read", "users.write"}, ceiling: userCeiling(fx)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, err := lg.c.UpdateUser(ctx, &core.UpdateUserRequest{ID: acct(lg.fx), ActorID: p.userID, DisplayName: "synthetic"})
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/users/%d", acct(fx)), map[string]any{"display_name": "synthetic"}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				dn := "synthetic"
				_, err := pb.NewUserServiceClient(lg.conn).UpdateUser(ctx, &pb.UpdateUserRequest{Id: uint32(acct(lg.fx)), DisplayName: &dn})
				return err
			},
		},
		{
			name: "user.delete", row: "DeleteUser", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(fx *fixtures, _ tgt, _ byte) requirement {
				return requirement{perms: []string{"users.read", "users.delete"}, ceiling: userCeiling(fx)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.DeleteUser(ctx, p.userID, acct(lg.fx))
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", acct(fx)), nil}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewUserServiceClient(lg.conn).DeleteUser(ctx, &pb.DeleteUserRequest{Id: uint32(acct(lg.fx))})
				return err
			},
		},
		userOp("user.restore", "RestoreUser", "users.write", http.MethodPost, "/restore",
			func(fx *fixtures) uint { return fx.ux.deletedUserID },
			func(ctx context.Context, lg *leg, p *principal) error {
				return lg.c.RestoreUser(ctx, p.userID, lg.fx.ux.deletedUserID)
			}),
		userOp("user.suspend", "SuspendUser", "users.write", http.MethodPost, "/suspend", acct,
			func(ctx context.Context, lg *leg, p *principal) error { return lg.c.SuspendUser(ctx, p.userID, acct(lg.fx)) }),
		userOp("user.reactivate", "ReactivateUser", "users.write", http.MethodPost, "/reactivate", acct,
			func(ctx context.Context, lg *leg, p *principal) error { return lg.c.ReactivateUser(ctx, p.userID, acct(lg.fx)) }),
		userOp("user.require.reset", "RequirePasswordReset", "users.write", http.MethodPost, "/require-password-reset", acct,
			func(ctx context.Context, lg *leg, p *principal) error {
				return lg.c.RequirePasswordReset(ctx, p.userID, acct(lg.fx))
			}),
		userOp("user.revoke.sessions", "RevokeUserSessions", "users.write", http.MethodPost, "/revoke-sessions", acct,
			func(ctx context.Context, lg *leg, p *principal) error {
				_, err := lg.c.RevokeUserSessions(ctx, p.userID, acct(lg.fx))
				return err
			}),
		userOp("user.resend.setup", "ResendAccountSetupLink", "users.write", http.MethodPost, "/resend-setup-link", acct,
			func(ctx context.Context, lg *leg, p *principal) error {
				_, err := lg.c.ResendAccountSetupLink(ctx, acct(lg.fx), p.userID)
				return err
			}),
	}
	reissue := userOp("user.reissue.otp", "ReissueOneTimePassword", "users.write", http.MethodPost, "/reissue-one-time-password", acct,
		func(ctx context.Context, lg *leg, p *principal) error {
			_, err := lg.c.ReissueOneTimePassword(ctx, p.userID, acct(lg.fx))
			return err
		})
	reissue.grpc = func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
		_, err := pb.NewUserServiceClient(lg.conn).ReissueOneTimePassword(ctx, &pb.ReissueOneTimePasswordRequest{Id: uint32(acct(lg.fx))})
		return err
	}
	// unlock is deliberately not ceiling-gated (login_lockout.go UnlockUser doc).
	unlock := userOp("user.unlock", "UnlockUser", "users.write", http.MethodPost, "/unlock", acct,
		func(ctx context.Context, lg *leg, p *principal) error { return lg.c.UnlockUser(ctx, p.userID, acct(lg.fx)) })
	unlock.req = func(*fixtures, tgt, byte) requirement { return requirement{perms: []string{"users.read", "users.write"}} }
	ops = append(ops, reissue, unlock)
	return append(ops, rolePhase5Ops()...)
}

func rolePhase5Ops() []opSpec {
	return []opSpec{
		{
			// replace u-acct's role set at P (it holds none there): global
			// roles.assign route gate inside the users.read group, then the
			// granter ceiling per added role.
			name: "user.roles.set", row: "SetUserRoles", targets: projTargets, grantArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), globalPerms: []string{"users.read", "roles.assign"}, ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, rid := grantRole(lg.fx, a)
				return lg.c.SetUserRoles(ctx, p.userID, acct(lg.fx), []uint{rid}, core.Scope{ProjectID: pid(lg.fx, t)}, p.isMachine())
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				_, rid := grantRole(fx, a)
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/users/%d/roles", acct(fx)), map[string]any{"role_ids": []uint{rid}, "project_id": pid(fx, t)}}
			},
		},
		{
			name: "userrole.assign", row: "AssignUserRole", targets: projTargets, grantArgs: true, selfMachineGranter: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, rid := grantRole(fx, a)
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), ceiling: []roleAt{{rid, pid(fx, t)}}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				_, rid := grantRole(lg.fx, a)
				return lg.c.AssignUserRole(ctx, p.userID, acct(lg.fx), rid, core.Scope{ProjectID: pid(lg.fx, t)}, p.isMachine())
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				_, rid := grantRole(fx, a)
				return restReq{http.MethodPost, "/api/v1/user-roles", map[string]any{"user_id": acct(fx), "role_id": rid, "project_id": pid(fx, t)}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				_, rid := grantRole(lg.fx, a)
				p := uint32(pid(lg.fx, t))
				_, err := pb.NewRoleServiceClient(lg.conn).AssignRole(ctx, &pb.AssignRoleRequest{UserId: uint32(acct(lg.fx)), RoleId: uint32(rid), ProjectId: &p})
				return err
			},
		},
		{
			// u-target holds project_viewer at A and B.
			name: "userrole.remove", row: "RemoveUserRole", targets: projTargets,
			req: atP("roles.assign"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				return lg.c.RemoveUserRole(ctx, p.userID, lg.fx.targetUserID, lg.fx.roleIDs["project_viewer"], core.Scope{ProjectID: pid(lg.fx, t)})
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodDelete, "/api/v1/user-roles", map[string]any{"user_id": fx.targetUserID, "role_id": fx.roleIDs["project_viewer"], "project_id": pid(fx, t)}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				p := uint32(pid(lg.fx, t))
				_, err := pb.NewRoleServiceClient(lg.conn).RemoveRole(ctx, &pb.RemoveRoleRequest{UserId: uint32(lg.fx.targetUserID), RoleId: uint32(lg.fx.roleIDs["project_viewer"]), ProjectId: &p})
				return err
			},
		},
		{
			// the role bundles secrets.read: the handler requires the actor to
			// hold it globally (resolveAndAuthorizePermissions).
			name: "role.create", row: "CreateRoleWithScope", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.read", "roles.write", "secrets.read"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, _, err := lg.c.CreateRoleWithScope(ctx, p.userID, "new-role", "synthetic", []uint{lg.fx.permIDs["secrets.read"]}, "project")
				return err
			},
			rest: func(*fixtures, tgt, byte) restReq {
				return restReq{http.MethodPost, "/api/v1/roles", map[string]any{"name": "new-role", "description": "synthetic", "permissions": []string{"secrets.read"}, "assignable_scope": "project"}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewRoleServiceClient(lg.conn).CreateRole(ctx, &pb.CreateRoleRequest{Name: "new-role", Description: "synthetic", Permissions: []string{"secrets.read"}, AssignableScope: "project"})
				return err
			},
		},
		{
			name: "role.update", row: "UpdateRole", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.read", "roles.write", "secrets.read"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				r, err := lg.ls.GetRole(ctx, lg.fx.ux.opsRoleID)
				if err != nil {
					return err
				}
				r.Description = "synthetic-updated"
				ids := []uint{lg.fx.permIDs["secrets.read"]}
				_, _, err = lg.c.UpdateRole(ctx, p.userID, r, &ids)
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", fx.ux.opsRoleID), map[string]any{"description": "synthetic-updated", "permissions": []string{"secrets.read"}}}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				d := "synthetic-updated"
				_, err := pb.NewRoleServiceClient(lg.conn).UpdateRole(ctx, &pb.UpdateRoleRequest{Id: uint32(lg.fx.ux.opsRoleID), Description: &d, Permissions: []string{"secrets.read"}})
				return err
			},
		},
		{
			name: "role.delete", row: "DeleteRole", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.read", "roles.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.DeleteRole(ctx, p.userID, lg.fx.ux.opsRoleID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", fx.ux.opsRoleID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, _ tgt, _ byte) error {
				_, err := pb.NewRoleServiceClient(lg.conn).DeleteRole(ctx, &pb.DeleteRoleRequest{Id: uint32(lg.fx.ux.opsRoleID)})
				return err
			},
		},
		{
			// the actor must hold the added permission globally.
			name: "role.perm.add", row: "AssignPermissionToRole", targets: []tgt{tGlobal}, selfMachineGranter: true,
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.read", "roles.write", "secrets.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.AssignPermissionToRole(ctx, p.userID, lg.fx.ux.opsRoleID, lg.fx.ux.permAddID, p.isMachine())
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/roles/%d/permissions", fx.ux.opsRoleID), map[string]any{"permission_id": fx.ux.permAddID}}
			},
		},
		{
			name: "role.perm.remove", row: "RemovePermissionFromRole", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{perms: []string{"roles.read", "roles.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.RemovePermissionFromRole(ctx, p.userID, lg.fx.ux.opsRoleID, lg.fx.ux.permRemoveID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d/permissions/%d", fx.ux.opsRoleID, fx.ux.permRemoveID), nil}
			},
		},
	}
}

// jsonNumberPositive reports whether the JSON body holds, at any envelope
// depth, a number under key that is > 0.
func jsonNumberPositive(body []byte, key string) bool {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(n any) bool {
		switch x := n.(type) {
		case map[string]any:
			if f, ok := x[key].(float64); ok && f > 0 {
				return true
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
