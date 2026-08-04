package contracttest

// pendingRegistry lists every operationId that has no 2xx JSON-Schema-bearing
// response in openapi.yaml yet. Every entry needs a reason -- this is a
// record of known gaps, not a dumping ground (ADR-074). Generated from a
// direct parse of openapi.yaml (see .scratch/classify_openapi.go in the PR
// that introduced this file) and verified equal to the spec via
// CheckPartition -- do not hand-edit without re-running that check.
//
// Adding a schema for an operation here does not require touching this map:
// CheckPartition fails the build if a pending entry's operation gains a
// schema, which is the signal to delete the entry -- the registry shrinks
// one operation at a time as ADR-074's Phase 2 handoff batches land.
var pendingRegistry = map[string]string{ // #nosec G101 -- operationId keys, not credentials; some contain "Token"/"PAT" (createPAT, issueMachineToken, ...), values are all the literal reason string "schema not yet written"
	"acknowledgeAnomalyAlert":        "schema not yet written", // post /api/v1/audit/anomalies/{id}/acknowledge
	"activateBreakGlass":             "schema not yet written", // post /api/v1/projects/{id}/break-glass
	"addGroupMember":                 "schema not yet written", // post /api/v1/groups/{id}/members
	"addProjectMember":               "schema not yet written", // post /api/v1/projects/{id}/members
	"assignPermissionToRole":         "schema not yet written", // post /api/v1/roles/{id}/permissions
	"assignRoleToGroup":              "schema not yet written", // post /api/v1/groups/{id}/roles
	"assignUserRole":                 "schema not yet written", // post /api/v1/user-roles
	"attestProjectAccessReview":      "schema not yet written", // post /api/v1/projects/{id}/access-review/attest
	"authConsumeSetup":               "schema not yet written", // post /auth/setup/consume
	"authLogout":                     "schema not yet written", // post /auth/logout
	"authPasswordReset":              "schema not yet written", // post /auth/password-reset
	"changePassword":                 "schema not yet written", // post /api/v1/auth/change-password
	"classifySecret":                 "schema not yet written", // patch /api/v1/secrets/{id}/classification
	"closeAccessReviewCampaign":      "schema not yet written", // post /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close
	"createAccessRequest":            "schema not yet written", // post /api/v1/projects/{id}/access-requests
	"createGlobalInvitation":         "schema not yet written", // post /api/v1/invitations
	"createGroup":                    "schema not yet written", // post /api/v1/groups
	"createMachineIdentity":          "schema not yet written", // post /api/v1/projects/{id}/machine-identities
	"createPAT":                      "schema not yet written", // post /api/v1/auth/tokens
	"createProject":                  "schema not yet written", // post /api/v1/projects
	"createProjectEnvironment":       "schema not yet written", // post /api/v1/projects/{id}/environments
	"createProjectInvitation":        "schema not yet written", // post /api/v1/projects/{id}/invitations
	"createRiskException":            "schema not yet written", // post /api/v1/risk-exceptions
	"createRole":                     "schema not yet written", // post /api/v1/roles
	"createRotationPolicy":           "schema not yet written", // post /api/v1/rotation-policies
	"createSecret":                   "schema not yet written", // post /api/v1/secrets
	"createSoDPolicy":                "schema not yet written", // post /api/v1/sod/policies
	"createUser":                     "schema not yet written", // post /api/v1/users
	"decideAccessReviewCampaignItem": "schema not yet written", // post /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide
	"deleteEnvironment":              "schema not yet written", // delete /api/v1/environments/{id}
	"deleteProject":                  "schema not yet written", // delete /api/v1/projects/{id}
	"deleteSoDPolicy":                "schema not yet written", // delete /api/v1/sod/policies/{id}
	"endImpersonation":               "schema not yet written", // post /api/v1/auth/end-impersonation
	"evaluateRotationPolicies":       "schema not yet written", // get /api/v1/rotation-policies/evaluate
	"exportAuditLogs":                "schema not yet written", // get /api/v1/audit/export
	"getAccessReviewCampaign":        "schema not yet written", // get /api/v1/projects/{id}/access-review/campaigns/{campaignId}
	"getAuditRetention":              "schema not yet written", // get /api/v1/audit/retention
	"getAuthConfig":                  "schema not yet written", // get /api/v1/system/auth-config
	"getAuthProfile":                 "schema not yet written", // get /api/v1/auth/profile
	"getComplianceControls":          "schema not yet written", // get /api/v1/compliance/controls
	"getComplianceEvidence":          "schema not yet written", // get /api/v1/compliance/evidence
	"getCompliancePosture":           "schema not yet written", // get /api/v1/compliance/posture
	"getDashboardActivity":           "schema not yet written", // get /api/v1/dashboard/activity
	"getDashboardStats":              "schema not yet written", // get /api/v1/dashboard/stats
	"getEncryptionConfig":            "schema not yet written", // get /api/v1/system/encryption-config
	"getGroup":                       "schema not yet written", // get /api/v1/groups/{id}
	"getGroupMembers":                "schema not yet written", // get /api/v1/groups/{id}/members
	"getGroupRoles":                  "schema not yet written", // get /api/v1/groups/{id}/roles
	"getLegalHold":                   "schema not yet written", // get /api/v1/legal-hold
	"getMostAccessedSecrets":         "schema not yet written", // get /api/v1/secrets/usage/most-accessed
	"getPermission":                  "schema not yet written", // get /api/v1/permissions/{id}
	"getProject":                     "schema not yet written", // get /api/v1/projects/{id}
	"getProjectAccessReview":         "schema not yet written", // get /api/v1/projects/{id}/access-review
	"getProjectDrift":                "schema not yet written", // get /api/v1/projects/{id}/drift
	"getRole":                        "schema not yet written", // get /api/v1/roles/{id}
	"getRolePermissions":             "schema not yet written", // get /api/v1/roles/{id}/permissions
	"getRotationPolicy":              "schema not yet written", // get /api/v1/rotation-policies/{id}
	"getRotationStatus":              "schema not yet written", // get /api/v1/rotation-policies/status
	"getSecret":                      "schema not yet written", // get /api/v1/secrets/{id}
	"getSecretRisk":                  "schema not yet written", // get /api/v1/secrets/{id}/risk
	"getSecretVersions":              "schema not yet written", // get /api/v1/secrets/{id}/versions
	"getSystemInfo":                  "schema not yet written", // get /api/v1/system/info
	"getSystemMetrics":               "schema not yet written", // get /api/v1/system/metrics
	"getUnusedSecrets":               "schema not yet written", // get /api/v1/secrets/usage/unused
	"getUser":                        "schema not yet written", // get /api/v1/users/{id}
	"getUserMembershipsForUser":      "schema not yet written", // get /api/v1/users/{id}/memberships
	"getUserRoleAssignment":          "schema not yet written", // get /api/v1/user-roles/user/{userId}
	"getUserRolesForUser":            "schema not yet written", // get /api/v1/users/{id}/roles
	"grantMachineRole":               "schema not yet written", // post /api/v1/projects/{id}/machine-identities/{machineId}/roles
	"grantSecretACL":                 "schema not yet written", // post /api/v1/secrets/{id}/acl
	"inviteMember":                   "schema not yet written", // post /api/v1/projects/{id}/memberships
	"issueMachineToken":              "schema not yet written", // post /api/v1/projects/{id}/machine-identities/{machineId}/tokens
	"liftLegalHold":                  "schema not yet written", // delete /api/v1/legal-hold
	"listAccessRequests":             "schema not yet written", // get /api/v1/projects/{id}/access-requests
	"listAccessReviewCampaigns":      "schema not yet written", // get /api/v1/projects/{id}/access-review/campaigns
	"listAnomalyAlerts":              "schema not yet written", // get /api/v1/audit/anomalies
	"listAuditLogs":                  "schema not yet written", // get /api/v1/audit/logs
	"listBreakGlassActivations":      "schema not yet written", // get /api/v1/projects/{id}/break-glass
	"listEnvironments":               "schema not yet written", // get /api/v1/environments
	"listGroups":                     "schema not yet written", // get /api/v1/groups
	"listMachineIdentities":          "schema not yet written", // get /api/v1/projects/{id}/machine-identities
	"listMachineTokens":              "schema not yet written", // get /api/v1/projects/{id}/machine-identities/{machineId}/tokens
	"listNotifications":              "schema not yet written", // get /api/v1/notifications
	"listPATs":                       "schema not yet written", // get /api/v1/auth/tokens
	"listPermissions":                "schema not yet written", // get /api/v1/permissions
	"listProjectEnvironments":        "schema not yet written", // get /api/v1/projects/{id}/environments
	"listProjectInvitations":         "schema not yet written", // get /api/v1/projects/{id}/invitations
	"listProjectMembers":             "schema not yet written", // get /api/v1/projects/{id}/members
	"listProjectMemberships":         "schema not yet written", // get /api/v1/projects/{id}/memberships
	"listProjects":                   "schema not yet written", // get /api/v1/projects
	"listRBACAuditLogs":              "schema not yet written", // get /api/v1/audit/rbac-logs
	"listRiskExceptions":             "schema not yet written", // get /api/v1/risk-exceptions
	"listRoles":                      "schema not yet written", // get /api/v1/roles
	"listRotationPolicies":           "schema not yet written", // get /api/v1/rotation-policies
	"listSecretShares":               "schema not yet written", // get /api/v1/secrets/{id}/shares
	"listSecrets":                    "schema not yet written", // get /api/v1/secrets
	"listSessions":                   "schema not yet written", // get /api/v1/auth/sessions
	"listSharedSecrets":              "schema not yet written", // get /api/v1/shared-secrets
	"listShares":                     "schema not yet written", // get /api/v1/shares
	"listSoDPolicies":                "schema not yet written", // get /api/v1/sod/policies
	"listSoDViolations":              "schema not yet written", // get /api/v1/sod/violations
	"listStaleUsers":                 "schema not yet written", // get /api/v1/users/stale
	"listUsers":                      "schema not yet written", // get /api/v1/users
	"markAllNotificationsRead":       "schema not yet written", // post /api/v1/notifications/read-all
	"markNotificationRead":           "schema not yet written", // post /api/v1/notifications/{id}/read
	"openAccessReviewCampaign":       "schema not yet written", // post /api/v1/projects/{id}/access-review/campaigns
	"placeLegalHold":                 "schema not yet written", // post /api/v1/legal-hold
	"reactivateUser":                 "schema not yet written", // post /api/v1/users/{id}/reactivate
	"removeMachineRole":              "schema not yet written", // delete /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}
	"removeProjectMember":            "schema not yet written", // delete /api/v1/projects/{id}/members/{userId}
	"requirePasswordReset":           "schema not yet written", // post /api/v1/users/{id}/require-password-reset
	"resendProjectInvitation":        "schema not yet written", // post /api/v1/projects/{id}/invitations/{invitationId}/resend
	"resendSetupLink":                "schema not yet written", // post /api/v1/users/{id}/resend-setup-link
	"resolveAccessRequest":           "schema not yet written", // put /api/v1/projects/{id}/access-requests/{requestId}
	"restoreEnvironment":             "schema not yet written", // post /api/v1/projects/{projectId}/environments/{id}/restore
	"restoreProject":                 "schema not yet written", // post /api/v1/projects/{id}/restore
	"restoreUser":                    "schema not yet written", // post /api/v1/users/{id}/restore
	"revokeBreakGlass":               "schema not yet written", // post /api/v1/projects/{id}/break-glass/{activationId}/revoke
	"revokeMachineToken":             "schema not yet written", // delete /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}
	"revokeProjectAccessReview":      "schema not yet written", // post /api/v1/projects/{id}/access-review/revoke
	"revokeProjectInvitation":        "schema not yet written", // delete /api/v1/projects/{id}/invitations/{invitationId}
	"revokeRiskException":            "schema not yet written", // delete /api/v1/risk-exceptions/{id}
	"revokeSecretACL":                "schema not yet written", // delete /api/v1/secrets/{id}/acl/{aclId}
	"rotateSecret":                   "schema not yet written", // post /api/v1/secrets/{id}/rotate
	"searchAuditLogs":                "schema not yet written", // get /api/v1/audit/search
	"searchUsers":                    "schema not yet written", // get /api/v1/users/search
	"shareSecret":                    "schema not yet written", // post /api/v1/secrets/{id}/share
	"startImpersonation":             "schema not yet written", // post /api/v1/admin/impersonate
	"suspendUser":                    "schema not yet written", // post /api/v1/users/{id}/suspend
	"transitionMachineIdentity":      "schema not yet written", // put /api/v1/projects/{id}/machine-identities/{machineId}
	"transitionMembership":           "schema not yet written", // put /api/v1/projects/{id}/memberships/{membershipId}
	"updateAuthProfile":              "schema not yet written", // put /api/v1/auth/profile
	"updateGroup":                    "schema not yet written", // put /api/v1/groups/{id}
	"updateProject":                  "schema not yet written", // put /api/v1/projects/{id}
	"updateProjectMember":            "schema not yet written", // put /api/v1/projects/{id}/members/{userId}
	"updateRole":                     "schema not yet written", // put /api/v1/roles/{id}
	"updateRotationPolicy":           "schema not yet written", // put /api/v1/rotation-policies/{id}
	"updateSecret":                   "schema not yet written", // put /api/v1/secrets/{id}
	"updateSharePermission":          "schema not yet written", // put /api/v1/shares/{id}
	"updateUser":                     "schema not yet written", // put /api/v1/users/{id}
	"updateUserRoles":                "schema not yet written", // put /api/v1/users/{id}/roles
	"verifyAuditChain":               "schema not yet written", // get /api/v1/audit/verify
	"verifyComplianceEvidence":       "schema not yet written", // post /api/v1/compliance/evidence/verify
	"withdrawAccessRequest":          "schema not yet written", // post /api/v1/projects/{id}/access-requests/{requestId}/withdraw
	"writeAuditCheckpoint":           "schema not yet written", // post /api/v1/audit/checkpoint
}

// outOfScopeRegistry lists every operationId that will never be enforced,
// by design, with the reason. Two shapes today:
//
//   - 204 No Content responses: nothing to validate a body against, by
//     definition (ADR-074) -- these are not gaps and don't belong in
//     pendingRegistry.
//   - prometheusMetrics: has a schema (text/plain), but it's promhttp's own
//     third-party handler, not code this repo owns, and no client will ever
//     be generated against Prometheus exposition format.
var outOfScopeRegistry = map[string]string{ // #nosec G101 -- operationId keys, not credentials; some contain "PAT"/"Session" (revokePAT, revokeSession, ...), values are all descriptive reason strings
	"deleteGroup":              "204 No Content -- no body to validate", // delete /api/v1/groups/{id}
	"deleteRole":               "204 No Content -- no body to validate", // delete /api/v1/roles/{id}
	"deleteRotationPolicy":     "204 No Content -- no body to validate", // delete /api/v1/rotation-policies/{id}
	"deleteSecret":             "204 No Content -- no body to validate", // delete /api/v1/secrets/{id}
	"deleteUser":               "204 No Content -- no body to validate", // delete /api/v1/users/{id}
	"removeGroupMember":        "204 No Content -- no body to validate", // delete /api/v1/groups/{id}/members/{userId}
	"removePermissionFromRole": "204 No Content -- no body to validate", // delete /api/v1/roles/{id}/permissions/{permissionId}
	"removeRoleFromGroup":      "204 No Content -- no body to validate", // delete /api/v1/groups/{id}/roles/{roleId}
	"removeUserRole":           "204 No Content -- no body to validate", // delete /api/v1/user-roles
	"revokePAT":                "204 No Content -- no body to validate", // delete /api/v1/auth/tokens/{id}
	"revokeSession":            "204 No Content -- no body to validate", // delete /api/v1/auth/sessions/{id}
	"revokeShare":              "204 No Content -- no body to validate", // delete /api/v1/shares/{id}

	"prometheusMetrics": "promhttp.Handler, third-party code, no generated client will ever read Prometheus exposition format", // get /metrics
}

// exercisingTests maps each enforced operationId to the top-level test
// function name(s) that call AssertOpenAPIResponse for it. This exists
// only so CheckAllEnforcedExercised can stay correct under CI's test
// sharding (server/http/handlers runs as 4 separate `go test -run <regexp>`
// processes, split by test-name hash -- see the CheckAllEnforcedExercised
// doc comment in checks.go for why a process-global check alone isn't
// enough). Keep this in sync with the actual test file: if you move an
// AssertOpenAPIResponse call to a different top-level test function, update
// its entry here too, or the coverage check will report a false failure
// (loud, not silent -- an out-of-date entry here fails closed).
var exercisingTests = map[string][]string{
	"authGetSetupToken":             {"TestGetSetupToken_HappyPath_S11"},
	"authLogin":                     {"TestLogin_HappyPath_S8"},
	"authRefresh":                   {"TestRefreshToken_ValidToken_S7"},
	"healthCheck":                   {"TestHealthCheck"},
	"listSecretACLs":                {"TestListSecretACLs_Empty"},
	"systemInit":                    {"TestAuthHandler_InitSystem_Success"},
	"exportSecretAccessLog":         {"TestExportAccessLog_JSONFormat", "TestExportAccessLog_CSVFormat"},
	"exportAuditLogsCSV":            {"TestExportAuditLogsCSV"},
	"exportAccessReviewCampaignCSV": {"TestExportAccessReviewCampaignCSV"},
}
