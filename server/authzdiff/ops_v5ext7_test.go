package authzdiff

import (
	"context"
	"fmt"
	"net/http"
)

// V5EXT7 ops: secret.schedule.set, secret.schedule.delete.
//
// Both are REST-only (no gRPC surface) and have core_refusal="none" in
// matrix.json, so coreEnforced=false: the route gate is the only authorization
// layer the oracle compares. The core leg is recorded n/a (errNotAuthzLayer); it
// is additionally marked coreGateExcluded to document that even if a core gate
// existed it would not re-check the router's permission gate.
//
// # secret.schedule.set (SetSecretSchedule)
//
// PUT /api/v1/secrets/{id}/schedule:
//
//	Route:  RequireScopedSecretPermission(permSecretsManage, "id")
//	Core:   SetSecretSchedule has no actorID parameter — it cannot check actor
//	        activity or permissions at all. coreGateExcluded=true.
//	Model:  atP("secrets.manage")
//	HARDENING-2 (carried from V5EXT7, documented in the report, NOT fixed as
//	product code here): no requireActorActive is possible without an actorID.
//
// # secret.schedule.delete (DeleteSecretSchedule)
//
// DELETE /api/v1/secrets/{id}/schedule: same structure as schedule.set.
// coreGateExcluded=true. HARDENING-2: same finding.
//
// secret.classify (ClassifySecret) is NOT bound here: ops_v5b1_test.go already binds
// it (V5 B1 rule 7, with the secretArgs fixtures and a real core leg). A second
// binding made the sweep run the op twice (subtest "secret.classify#01"), which
// authzgate's check-log rejects. Only its router-gate anchor test lives in
// sweep_v5ext7_test.go.
//
// What these oracles do NOT verify:
//   - schedule.set/delete: whether a schedule actually takes effect on reads (the
//     temporal access window is not modelled); LogSecretScheduleSet/
//     LogSecretScheduleDeleted audit events; a suspended-actor refusal (HARDENING-2:
//     there is no actorID to check).
func v5ext7Ops() []opSpec {
	return scheduleOps()
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
			// coreGateExcluded: SetSecretSchedule has no actorID; it cannot perform
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

// isV5ext7Op reports whether name is covered by TestV5ext7StrictSweep.
func isV5ext7Op(name string) bool {
	switch name {
	case "secret.schedule.set", "secret.schedule.delete":
		return true
	}
	return false
}
