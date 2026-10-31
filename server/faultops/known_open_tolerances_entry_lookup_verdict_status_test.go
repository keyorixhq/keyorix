// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

// Oracle (h) (#3457, lookup_verdict_status_oracle_test.go) findings that are real,
// filed and not yet fixed: a fault on a permission or credential lookup still
// answers 401/403 instead of 503/Unavailable. Every row is one (op, method, nth,
// kind) the oracle observed at origin/main @ ad272b323, nothing wider, and cites
// #3873. The PR that fixes a case deletes its row (TestKnownOpenTolerances_AreLoadBearing
// reports a row the oracle no longer consults). #3870 (AUTHZ-OUTAGE-HANDLERS-1) and
// AUTHZ-OUTAGE-TAILS-1 are the expected fixers of the handler rows; the auth-endpoint
// rows (end-impersonation, refresh, step-up, WebAuthn finish) sit in the login/MFA
// handlers owned by FIX-3277.
func init() {
	for _, r := range []struct {
		name, op, method string
		nth              int
		kind             faultstorage.FaultKind
	}{
		{"grpc_keyorix_v1_secretservice_deletesecret_resolveuserpermissionat_2_effect_then_error", "GRPC keyorix.v1.SecretService.DeleteSecret", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"grpc_keyorix_v1_secretservice_deletesecret_resolveuserpermissionat_2_error", "GRPC keyorix.v1.SecretService.DeleteSecret", "ResolveUserPermissionAt", 2, faultstorage.KindError},
		{"grpc_keyorix_v1_secretservice_updatesecret_resolveuserpermissionat_2_effect_then_error", "GRPC keyorix.v1.SecretService.UpdateSecret", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"grpc_keyorix_v1_secretservice_updatesecret_resolveuserpermissionat_2_error", "GRPC keyorix.v1.SecretService.UpdateSecret", "ResolveUserPermissionAt", 2, faultstorage.KindError},
		{"rest_delete_api_v1_secrets_id_resolveuserpermissionat_2_effect_then_error", "REST DELETE /api/v1/secrets/{id}", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"rest_delete_api_v1_secrets_id_resolveuserpermissionat_2_error", "REST DELETE /api/v1/secrets/{id}", "ResolveUserPermissionAt", 2, faultstorage.KindError},
		{"rest_patch_api_v1_secrets_id_description_resolveuserpermissionat_2_effect_then_error", "REST PATCH /api/v1/secrets/{id}/description", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"rest_patch_api_v1_secrets_id_description_resolveuserpermissionat_2_error", "REST PATCH /api/v1/secrets/{id}/description", "ResolveUserPermissionAt", 2, faultstorage.KindError},
		{"rest_post_api_v1_auth_mfa_stepup_getuser_1_effect_then_error", "REST POST /api/v1/auth/mfa/stepup", "GetUser", 1, faultstorage.KindEffectThenError},
		{"rest_post_api_v1_auth_mfa_stepup_getuser_1_error", "REST POST /api/v1/auth/mfa/stepup", "GetUser", 1, faultstorage.KindError},
		{"rest_post_api_v1_rotation_policies_resolveuserpermissionat_1_effect_then_error", "REST POST /api/v1/rotation-policies/", "ResolveUserPermissionAt", 1, faultstorage.KindEffectThenError},
		{"rest_post_api_v1_rotation_policies_resolveuserpermissionat_1_error", "REST POST /api/v1/rotation-policies/", "ResolveUserPermissionAt", 1, faultstorage.KindError},
		{"rest_post_api_v1_secrets_id_move_resolveuserpermissionat_2_effect_then_error", "REST POST /api/v1/secrets/{id}/move", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"rest_post_api_v1_secrets_id_move_resolveuserpermissionat_2_error", "REST POST /api/v1/secrets/{id}/move", "ResolveUserPermissionAt", 2, faultstorage.KindError},
		{"rest_post_auth_refresh_getuser_1_effect_then_error", "REST POST /auth/refresh", "GetUser", 1, faultstorage.KindEffectThenError},
		{"rest_post_auth_webauthn_login_finish_getuserpermissions_1_effect_then_error", "REST POST /auth/webauthn/login/finish", "GetUserPermissions", 1, faultstorage.KindEffectThenError},
		{"rest_put_api_v1_secrets_id_resolveuserpermissionat_2_effect_then_error", "REST PUT /api/v1/secrets/{id}", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"rest_put_api_v1_secrets_id_resolveuserpermissionat_2_error", "REST PUT /api/v1/secrets/{id}", "ResolveUserPermissionAt", 2, faultstorage.KindError},
		{"rest_put_api_v1_secrets_id_tags_resolveuserpermissionat_2_effect_then_error", "REST PUT /api/v1/secrets/{id}/tags", "ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError},
		{"rest_put_api_v1_secrets_id_tags_resolveuserpermissionat_2_error", "REST PUT /api/v1/secrets/{id}/tags", "ResolveUserPermissionAt", 2, faultstorage.KindError},
	} {
		registerKnownOpenTolerance("lookup_verdict_"+r.name, knownOpenTolerance{
			op: r.op, method: r.method, nth: r.nth, kind: r.kind, oracle: "h",
			issue: "#3873", expires: "2026-12-31", findingDoc: "#3873",
		})
	}
}
