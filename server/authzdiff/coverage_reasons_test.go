package authzdiff

import "strings"

// uncoveredReason says why an in-scope matrix operation is NOT exercised by
// the harness, in one of the three classes the review asked for:
//
//	fixture: — needs a fixture or configuration the harness does not have
//	model:   — no reference-model rule for its authorization yet
//	design:  — skipped by design (outside this campaign's scope, or not an
//	           authorization decision the three layers can disagree on)
//
// An exact key in uncoveredReasons wins; otherwise the first matching rule in
// reasonRules. TestCoverageAllIsCurrent fails on an uncovered op neither
// matches, so a new in-scope op cannot go unexplained.
func uncoveredReason(key, _ string) string {
	if r, ok := uncoveredReasons[key]; ok {
		return r
	}
	for _, rr := range reasonRules {
		if strings.Contains(key, rr.match) {
			return rr.reason
		}
	}
	return ""
}

const notRequested = "design: outside the families requested for this campaign (groups, projects, machine identities, invitations, access requests, memberships, secrets); not bound"

var reasonRules = []struct{ match, reason string }{
	// pre-authentication / credential-establishment flows: no authenticated principal to compare
	{" /auth/login", "design: pre-authentication endpoint (establishes the credential); no principal whose authorization the layers could disagree on"},
	{" /auth/logout", "design: acts only on the caller's own session; not an authorization decision"},
	{" /auth/refresh", "design: credential renewal for the caller's own session; not an authorization decision"},
	{" /auth/password-reset", "design: pre-authentication flow driven by a reset token"},
	{" /auth/setup/consume", "design: pre-authentication flow driven by a setup token"},
	{" /auth/mfa/verify", "fixture: needs an MFA-enrolled principal mid-login (MFA deferred to the not-yet list)"},
	{" /auth/sso/", "fixture: needs a configured OIDC identity provider"},
	{" /auth/saml/", "fixture: needs a configured SAML identity provider"},
	{" /auth/webauthn/", "fixture: needs a WebAuthn authenticator"},
	{" /api/v1/auth/webauthn/", "fixture: needs a WebAuthn authenticator"},
	{" /api/v1/auth/mfa/", "fixture: needs MFA enrolment state (MFA deferred to the not-yet list)"},
	{" /api/v1/auth/", "design: self-service on the caller's own account/credentials (no target owned by someone else); not bound"},
	{" /api/v1/end-impersonation", "fixture: needs an impersonation session (deferred to the not-yet list)"},
	{" /api/v1/admin/impersonate", "fixture: needs an impersonation session (deferred to the not-yet list)"},
	{" /system/init", "design: one-time bootstrap of an uninitialised install; the template is already initialised"},
	{" /scim/v2/", "fixture: needs the SCIM bearer token and an IdP-managed principal (SCIM principals deferred to the not-yet list)"},
	{"DynamicSecretService.", "fixture: needs a dynamic-secret backend (database/cloud) configured"},
	{" /api/v1/dynamic-secrets/", "fixture: needs a dynamic-secret backend (database/cloud) configured"},
	{"ConnectService.", "fixture: needs a Keyorix Connect connector configured"},
	{" /api/v1/connect/", "fixture: needs a Keyorix Connect connector configured"},
	{"BreakGlassService.", "model: break-glass activation/approval semantics are not in the reference model (deferred to the not-yet list)"},
	{"/break-glass", "model: break-glass activation/approval semantics are not in the reference model (deferred to the not-yet list)"},
	{"/access-review", "model: access-review campaign/attestation rules are not in the reference model"},
	{" /api/v1/sod/", "model: separation-of-duties conflict rules are not in the reference model"},
	{" /api/v1/risk-exceptions", "model: risk-exception approval rules are not in the reference model"},
	{" /api/v1/legal-hold", "model: legal-hold rules are not in the reference model"},
	{" /api/v1/mfa-reset-requests", "model: MFA-reset approval rules are not in the reference model"},
	{" /api/v1/admin/jobs/", "design: on-demand job trigger (system.write / alerts.write); outside the requested families; not bound"},
	{" /api/v1/admin/anomaly-config", notRequested},
	{" /api/v1/audit/", notRequested},
	{"AuditService.", notRequested},
	{" /api/v1/compliance/", notRequested},
	{" /api/v1/notification", notRequested},
	{" /api/v1/alert-escalation-policies", notRequested},
	{" /api/v1/rejection-reason-templates", notRequested},
	{" /api/v1/rotation-policies", notRequested},
	{" /api/v1/secret-templates", notRequested},
	{" /api/v1/folders", notRequested},
	{" /api/v1/environments/", notRequested},
	{" /api/v1/roles", notRequested},
	{"RoleService.", notRequested},
	{" /api/v1/user-roles", notRequested},
	{" /api/v1/users", notRequested},
	{"UserService.", notRequested},
}

// Secrets family: requested, but Phase 2 bound only an initial set of
// secret operations. Each remaining one is listed with what binding it needs.
var uncoveredReasons = map[string]string{
	"REST POST /api/v1/projects/{id}/environments/{envId}/clone":                 "fixture: bulk secret copy into a second environment; needs a clean target environment per case (not bound)",
	"REST POST /api/v1/projects/{id}/environments/{envId}/copy-secrets":          "fixture: bulk secret copy into a second environment; needs a clean target environment per case (not bound)",
	"GRPC keyorix.v1.SecretService.CreateSecret":                                 "design: secret create was not in the initially bound secret set; not bound (model rule exists: secrets.write)",
	"REST POST /api/v1/secrets":                                                  "design: secret create was not in the initially bound secret set; not bound (model rule exists: secrets.write)",
	"GRPC keyorix.v1.ShareService.RevokeShare":                                   "fixture: needs a share-record id exposed by the fixture (s2's shares exist but their ids are not captured)",
	"GRPC keyorix.v1.ShareService.UpdateSharePermission":                         "fixture: needs a share-record id exposed by the fixture (s2's shares exist but their ids are not captured)",
	"REST DELETE /api/v1/shares/{id}":                                            "fixture: needs a share-record id exposed by the fixture (s2's shares exist but their ids are not captured)",
	"REST PUT /api/v1/shares/{id}":                                               "fixture: needs a share-record id exposed by the fixture (s2's shares exist but their ids are not captured)",
	"REST DELETE /api/v1/secrets/{id}/self-share":                                "fixture: needs a share to the calling principal per case",
	"REST DELETE /api/v1/secrets/{id}/dependencies/{depId}":                      "fixture: needs a secret-dependency row",
	"REST POST /api/v1/secrets/{id}/dependencies":                                "fixture: needs a second secret to depend on and dependency-cycle rules",
	"REST DELETE /api/v1/secrets/{id}/schedule":                                  "model: time-window access schedules are not in the reference model",
	"REST PUT /api/v1/secrets/{id}/schedule":                                     "model: time-window access schedules are not in the reference model",
	"REST DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}": "fixture: needs a version comment",
	"REST POST /api/v1/secrets/{id}/versions/{versionId}/comments":               "fixture: needs a version id exposed by the fixture",
	"REST GET /api/v1/secrets/{id}/certificate":                                  "fixture: needs a certificate-type secret",
	"REST PATCH /api/v1/secrets/{id}/classification":                             "model: restricted-classification gate rules are not in the reference model",
	"REST POST /api/v1/secret-access-requests":                                   "model: restricted-classification secret-access rules are not in the reference model",
	"REST POST /api/v1/secret-access-requests/{requestId}/withdraw":              "model: restricted-classification secret-access rules are not in the reference model",
	"REST PUT /api/v1/secret-access-requests/{requestId}":                        "model: restricted-classification secret-access rules are not in the reference model",
	"REST PATCH /api/v1/secrets/{id}/description":                                "design: metadata edit outside the initially bound secret set; not bound",
	"REST PATCH /api/v1/secrets/{id}/retention":                                  "design: metadata edit outside the initially bound secret set; not bound",
	"REST PUT /api/v1/secrets/{id}/tags":                                         "design: metadata edit outside the initially bound secret set; not bound",
	"REST POST /api/v1/projects/{id}/secrets/bulk-delete":                        "design: bulk secret operation outside the initially bound secret set; not bound",
	"REST POST /api/v1/projects/{id}/secrets/bulk-rename":                        "design: bulk secret operation outside the initially bound secret set; not bound",
	"REST POST /api/v1/projects/{id}/secrets/bulk-rotate":                        "design: bulk secret operation outside the initially bound secret set; not bound",
	"REST POST /api/v1/projects/{id}/secrets/extend-expiring":                    "fixture: needs expiring secrets",
	"REST POST /api/v1/projects/{id}/secrets/reassign-owner":                     "design: bulk secret operation outside the initially bound secret set; not bound",
	"REST POST /api/v1/projects/{id}/secrets/render":                             "fixture: needs a template referencing secrets",
	"REST POST /api/v1/projects/{id}/secrets/resume-all":                         "design: bulk secret operation outside the initially bound secret set; not bound",
	"REST POST /api/v1/projects/{id}/secrets/suspend-all":                        "design: bulk secret operation outside the initially bound secret set; not bound",
	"REST POST /api/v1/secrets/{id}/copy":                                        "fixture: needs a clean target environment per case",
	"REST POST /api/v1/secrets/{id}/move":                                        "fixture: needs a folder to move into",
	"REST POST /api/v1/secrets/{id}/restore":                                     "fixture: needs a soft-deleted secret",
	"REST POST /api/v1/secrets/{id}/resume":                                      "fixture: needs a suspended secret",
	"REST POST /api/v1/secrets/{id}/suspend":                                     "design: lifecycle op outside the initially bound secret set; not bound",
	"REST POST /api/v1/secrets/{id}/rollback":                                    "fixture: needs a secret with two or more versions",
	"REST POST /api/v1/secrets/{id}/rotate":                                      "design: rotation outside the initially bound secret set; not bound (auto-rotate is covered)",
	"REST POST /api/v1/secrets/{id}/rotation/simulate":                           "design: rotation outside the initially bound secret set; not bound (auto-rotate is covered)",
	"REST POST /api/v1/secrets/{id}/transfer-ownership":                          "model: ownership semantics are not in the reference model",
}
