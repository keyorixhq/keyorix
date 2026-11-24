package authzdiff

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core"
)

// V5EXT3 ops: bulk-secret operations — bulk-delete, bulk-rename, bulk-suspend,
// and resume-all. These are the five bulk-secret endpoints COVERAGE-ALL.md
// marked "design: not bound"; this session binds four of them (bulk-rotate is
// still deferred — see LEFTOVERS in the report).
//
// # Authorization model for bulk-secret ops
//
// Every bulk-secret endpoint has a REST router gate (RequireScopedPermission at
// project scope) and a core per-item authorization check
// (EnforceSecretWritePermission / EnforceSecretOwnerPermission → CheckSecretPermission).
// The per-item check includes an RBAC fallback (#r124): a user holding the
// relevant permission via RBAC at {project, secret.env} satisfies it without
// owning the secret. For the standard fixture (env=0 all-environments grants, all
// secrets in the default environment), the RBAC fallback resolves identically to
// the router gate — both check the same permission at the same effective scope.
// Core and REST therefore AGREE for every standard-sweep principal.
//
// # Machine actors
//
// All four ops use the caller's userID (not machineID) in core:
//   - BulkRenameSecrets, SuspendProjectSecretsWithOptions, ResumeProjectSecrets:
//     return error immediately for actorID==0 ("project ID and actor ID are required").
//   - BulkDeleteSecrets: actorID==0 triggers the CLI bypass — the code calls
//     GetSecret (no permission check) and DeleteSecret (no permission check) directly.
//     A machine holding secrets.delete passes the router gate and the CLI bypass
//     deletes the secret; Deleted=[id], so REST=allowed and model=allowed agree.
//
// In all cases the core leg returns errNotAuthzLayer for machine actors: the
// per-item checks are not authoritative for machines (the router gate is the
// authoritative check). BulkRenameSecrets / Suspend / Resume refuse a machine
// actor with ErrPermissionDenied and REST answers 403 (#4514), so the model
// marks them human-only (humanOnlyOps); the former waiver known-10 is gone.
//
// # What these oracles do NOT verify
//
//   - Ownership-only grants: a user who owns a secret but lacks the RBAC
//     permission is skipped per secret by rename, suspend-all, resume-all and
//     extend-expiring since CORE-AUTHZ-RACE-NOV-1 item 2 (enforceSecretWriteGate,
//     the #4508 sibling), as the REST router gate refuses them; bulk-delete keeps
//     its own owner rule. The owner principal is not among these ops' fixtures.
//   - Env-scoped grants: CheckSecretPermission checks {project, secret.env};
//     a grant scoped to a specific environment is exercised by the secret.read.env
//     binding (ops_v5b_test.go), not here.
//   - Per-item business rejections: naming-policy violations (rename), already-
//     suspended state (suspend/resume), partial failures — not authz decisions.
//   - Audit trail and side-effect correctness.
func v5ext3Ops() []opSpec {
	return append(bulkSecretDeleteRenameOps(), bulkSecretSuspendResumeOps()...)
}

// ---- bulk-delete + bulk-rename ----
//
// POST /api/v1/projects/{id}/secrets/bulk-delete:
//
//	Router gate: RequireScopedPermission(permSecretsDelete, projectScope)
//	Core gate: BulkDeleteSecrets → bulkDeleteOneSecret → DeleteSecretWithPermissionCheck
//	  → EnforceSecretOwnerPermission → CheckSecretPermission(PermissionOwner) with
//	  RBAC fallback for secrets.delete.
//	Model: secrets.delete @ project, plus secrets.read @ project for a user actor:
//	  each item is first read through GetSecretWithPermissionCheck (#4515). A
//	  machine actor takes the actorID=0 path, which reads without a check.
//	restOK: the fixture secretID must appear in the "deleted" list.
//	core: machine → errNotAuthzLayer; user → check Deleted list.
//
// POST /api/v1/projects/{id}/secrets/bulk-rename:
//
//	Router gate: RequireScopedPermission(permSecretsWrite, projectScope)
//	Core gate: BulkRenameSecrets → secrets.write @ project (requireScopedGate,
//	  before any entry is read; #4657), then the per-entry EnforceSecretWritePermission
//	  re-check with RBAC fallback. The batch carries s3 (viewer ACL write in A) so a
//	  per-entry-only core shows as a core-only over-allow (bulkRenameRequest).
//	Model: secrets.write @ project.
//	restOK: jsonNumberPositive(b, "renamed") — renamed > 0.
//	core: machine → errNotAuthzLayer; user → check Renamed > 0.
func bulkSecretDeleteRenameOps() []opSpec {
	return []opSpec{
		{
			name: "bulk.delete", row: "BulkDeleteSecrets", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"secrets.delete"}, userPerms: []string{"secrets.read"}, scope: pid(fx, t)}
			},
			restOK: func(b []byte, fx *fixtures, t tgt) bool {
				return jsonListHas(b, "deleted", fx.proj(byte(t)).secretID)
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				pp := lg.fx.proj(byte(t))
				result, err := lg.c.BulkDeleteSecrets(ctx, core.BulkDeleteRequest{SecretIDs: []uint{pp.secretID}},
					pp.projectID, p.username, p.userID, "127.0.0.1", "authzdiff-test")
				if err != nil {
					return err
				}
				if slices.Contains(result.Deleted, pp.secretID) {
					return nil
				}
				return errItemRefused
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/secrets/bulk-delete", pp.projectID),
					map[string]any{"secret_ids": []uint{pp.secretID}}}
			},
		},
		{
			name: "bulk.rename", row: "BulkRenameSecrets", targets: projTargets,
			req: atP("secrets.write"),
			restOK: func(b []byte, _ *fixtures, _ tgt) bool {
				return jsonNumberPositive(b, "renamed")
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				pp := lg.fx.proj(byte(t))
				report, err := lg.c.BulkRenameSecrets(ctx, pp.projectID, bulkRenameRequest(pp),
					false, p.username, p.userID, "127.0.0.1", "authzdiff-test")
				if err != nil {
					return err
				}
				if report.Renamed == 0 {
					return errItemRefused
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				renames := make([]map[string]any, 0, 2)
				for _, rn := range bulkRenameRequest(pp) {
					renames = append(renames, map[string]any{"id": rn.ID, "new_name": rn.NewName})
				}
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/secrets/bulk-rename", pp.projectID),
					map[string]any{"renames": renames}}
			},
		},
	}
}

// bulkRenameRequest is the rename batch both legs send: the main fixture secret
// (admin-owned, no grant for a probed principal) and s3, on which the viewer holds
// a per-secret ACL secrets.write in A (world_test.go). s3 is what exposes a core
// that decides the batch per secret only (#4657): REST refuses the viewer at the
// route gate, so core must refuse them too, not rename s3.
func bulkRenameRequest(pp *perProject) []core.SecretRename {
	return []core.SecretRename{
		{ID: pp.secretID, NewName: "s-renamed-by-authzdiff"},
		{ID: pp.secrets[3].id, NewName: "s3-renamed-by-authzdiff"},
	}
}

// ---- bulk-suspend + resume-all ----
//
// POST /api/v1/projects/{id}/secrets/suspend-all:
//
//	Router gate: RequireScopedPermission(permSecretsWrite, projectScope)
//	Core gate: SuspendProjectSecretsWithOptions → secrets.write @ project
//	  (requireScopedGate, before any secret is read; #4161 row 25), then the
//	  per-item EnforceSecretWritePermission re-check with RBAC fallback.
//	Model: secrets.write @ project.
//	restOK: jsonNumberPositive(b, "suspended") — at least one secret was suspended.
//	Positive control calibration: the fixture always has active secrets (pp.secretID
//	and pp.secrets[1..3]), so an admin with secrets.write suspends n > 0.
//	core: machine → errNotAuthzLayer; user → n==0 → errItemRefused.
//
// POST /api/v1/projects/{id}/secrets/resume-all:
//
//	Router gate: RequireScopedPermission(permSecretsWrite, projectScope)
//	Core gate: ResumeProjectSecrets → secrets.write @ project (requireScopedGate,
//	  before any secret is read; #4657), then the per-item EnforceSecretWritePermission
//	  re-check with RBAC fallback. In A the viewer holds a per-secret ACL write on
//	  s-resume-fixture, so a per-item-only core shows as a core-only over-allow.
//	Model: secrets.write @ project.
//	restOK: jsonNumberPositive(b, "resumed") — at least one secret was resumed.
//	Positive control calibration: pp.suspendedSecretID is pre-suspended in the
//	V5EXT3 seed (world_test.go), so an admin with secrets.write resumes n ≥ 1.
//	core: machine → errNotAuthzLayer; user → n==0 → errItemRefused.
func bulkSecretSuspendResumeOps() []opSpec {
	return []opSpec{
		{
			name: "bulk.suspend", row: "SuspendProjectSecretsWithOptions", targets: projTargets,
			req: atP("secrets.write"),
			restOK: func(b []byte, _ *fixtures, _ tgt) bool {
				return jsonNumberPositive(b, "suspended")
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				pp := lg.fx.proj(byte(t))
				n, err := lg.c.SuspendProjectSecrets(ctx, pp.projectID, p.userID, "authzdiff-test-suspend")
				if err != nil {
					return err
				}
				if n == 0 {
					return errItemRefused
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/secrets/suspend-all", pp.projectID), nil}
			},
		},
		{
			name: "resume.all", row: "ResumeProjectSecrets", targets: projTargets,
			req: atP("secrets.write"),
			restOK: func(b []byte, _ *fixtures, _ tgt) bool {
				return jsonNumberPositive(b, "resumed")
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				pp := lg.fx.proj(byte(t))
				n, err := lg.c.ResumeProjectSecrets(ctx, pp.projectID, p.userID)
				if err != nil {
					return err
				}
				if n == 0 {
					return errItemRefused
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/secrets/resume-all", pp.projectID), nil}
			},
		},
	}
}

// isV5ext3Op reports whether name is one of the V5EXT3 bindings.
func isV5ext3Op(name string) bool {
	for _, s := range v5ext3Ops() {
		if s.name == name {
			return true
		}
	}
	return false
}
