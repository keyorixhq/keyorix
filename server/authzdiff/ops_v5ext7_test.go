package authzdiff

import (
	"context"
	"fmt"
	"net/http"
)

// V5EXT7 ops: secret.schedule.set, secret.schedule.delete, secret.classify.
//
// All three are REST-only (no gRPC surface). All three are coreGateExcluded:
// the core functions do not perform RBAC authorization themselves.
//
// # secret.schedule.set (SetSecretSchedule)
//
// PUT /api/v1/secrets/{id}/schedule:
//
//	Route:  RequireScopedSecretPermission(permSecretsManage, "id")
//	Core:   SetSecretSchedule has no actorID parameter — cannot check actor
//	        activity or permissions. coreGateExcluded=true.
//	Model:  atP("secrets.manage")
//	HARDENING-2: no requireActorActive possible (no actorID); see report.
//
// # secret.schedule.delete (DeleteSecretSchedule)
//
// DELETE /api/v1/secrets/{id}/schedule:
//
//	Same structure as schedule.set. coreGateExcluded=true.
//	HARDENING-2: same finding.
//
// # secret.classify (ClassifySecret)
//
// PATCH /api/v1/secrets/{id}/classification:
//
//	Route:  RequireScopedSecretPermission(permSecretsWrite, "id", SecretActionClassify)
//	Core:   ClassifySecret takes actorID but does NOT call requireActorActive or
//	        Authorize — it only validates inputs and writes the field directly.
//	        coreGateExcluded=true.
//	Model:  atP("secrets.write")
//	HARDENING-1: requireActorActive missing in ClassifySecret; see report.
//
// What these oracles do NOT verify:
//   - schedule.set/delete: whether a schedule actually takes effect on reads
//     (the temporal access window is not modelled). LogSecretScheduleSet/
//     LogSecretScheduleDeleted audit events.
//   - secret.classify: the restricted-classification downgrade gate
//     (checkRestrictedSecretReadApproval) — fixture plainID is not classified
//     "restricted", so that code path is never triggered.
func v5ext7Ops() []opSpec {
	return append(scheduleOps(), classifyOps()...)
}

// ---- schedule ops ----

func scheduleOps() []opSpec {
	scheduleBody := map[string]any{
		"allowed_days": "1,2,3,4,5",
		"start_hour":   9,
		"end_hour":     17,
		"timezone":     "UTC",
	}
	return []opSpec{
		{
			name: "secret.schedule.set", row: "SetSecretSchedule", targets: projTargets,
			req: atP("secrets.manage"),
			// coreGateExcluded: SetSecretSchedule has no actorID; cannot perform
			// RBAC or actor-state checks. The route gate is the only authorization layer.
			coreGateExcluded: true,
			core: func(_ context.Context, _ *leg, _ *principal, _ tgt, _ byte) error {
				return errNotAuthzLayer
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", sxOf(fx, t).plainID), scheduleBody}
			},
		},
		{
			name: "secret.schedule.delete", row: "DeleteSecretSchedule", targets: projTargets,
			req: atP("secrets.manage"),
			// coreGateExcluded: same as schedule.set.
			coreGateExcluded: true,
			core: func(_ context.Context, _ *leg, _ *principal, _ tgt, _ byte) error {
				return errNotAuthzLayer
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/schedule", sxOf(fx, t).plainID), nil}
			},
		},
	}
}

// ---- classify op ----

func classifyOps() []opSpec {
	return []opSpec{
		{
			name: "secret.classify", row: "ClassifySecret", targets: projTargets,
			req: atP("secrets.write"),
			// coreGateExcluded: ClassifySecret does not call Authorize or
			// requireActorActive. The route gate (RequireScopedSecretPermission with
			// SecretActionClassify) is the only authorization layer. See HARDENING-1.
			coreGateExcluded: true,
			core: func(_ context.Context, _ *leg, _ *principal, _ tgt, _ byte) error {
				return errNotAuthzLayer
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/classification", sxOf(fx, t).plainID), map[string]any{"level": "public"}}
			},
		},
	}
}

