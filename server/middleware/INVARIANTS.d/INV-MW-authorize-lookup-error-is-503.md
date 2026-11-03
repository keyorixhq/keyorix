- **INV-MW-authorize-lookup-error-is-503** When the PERMISSION lookup behind a gate fails
  because storage is unavailable (the request context was canceled or hit its deadline, a
  credential/role lookup was classified transient, or the database connection itself failed:
  `core.IsAuthorizeTransient`, structural `errors.Is`/`errors.As` on sentinels and driver/net
  error types, never message text) the request is REFUSED with 503, `Retry-After` and the
  fixed message "authorization temporarily unavailable, please retry"
  (`authorizeLookupUnavailable`), and over gRPC with `codes.Unavailable` and the same fixed
  message (`authorizeRefusal`), not 403 / `PermissionDenied`: a client retries 503 and does not
  retry a denial. It holds at the middleware gates and the gRPC sites listed here
  (`finishScopedPermissionRequest`, `RequirePermissionInAnyScope`, the global-scope probe of
  `handleScopeResolutionError`, the secret fetch of the per-secret gates, and the gRPC
  `authorizeScoped`, `authorizeScopedTarget`, `authorizeSecretScoped`, `authorizeShareScoped`,
  `CreateSecret`, `ListSecrets`) and at the REST routes that check the permission inside the
  handler, through `refuseUnlessAuthorized` (server/http/handlers, over
  `core.IsAuthorizeTransient`, same 503 / `Retry-After` / fixed message): `POST /api/v1/secrets`
  (`CreateSecret`), `GET /api/v1/secrets` (the machine-principal check in `ListSecrets`), the
  machine fallback check in `GetSecret`, secret copy, folder create, and the dynamic-secrets
  `authorize`/`denyAuthz` pair. It does NOT yet hold for the `AuthorizedAtGlobalScope` callers
  (AUTHZ-OUTAGE-TAILS-1), and three further in-handler `roles.assign` / `secrets.write`
  checks still answer 403 on an outage (`catalog.go` `UpdateProject`, `invitations.go`
  `CreateGlobalInvitation`, `rotation_policies_handler.go` `Create`); they are named, with
  the reason, in `authorizeOutageExempt` and tracked in a follow-up issue. The human-principal
  scoped listing in `ListSecrets` does not refuse on a failed check: it falls back to the
  caller's owned and ACL-granted secrets, so it is outside this invariant (it answers 5xx if
  that read fails too). The handler
  behind the gate is never invoked on a fault; nothing is cached; a value read's denial note
  records `internal_error` (outcome=failed), not `forbidden`, so the outage is not counted as a
  denial of the caller. `(allowed=false, err=nil)` stays 403 / `PermissionDenied` with the same
  body and note, a PAT whose restriction disallows the permission still answers 403 with no
  storage access, and an error that is not an outage (for example `errNoPrincipalPermission`)
  stays a fail-closed, logged 403 / `PermissionDenied`. No decision changes: fail-closed before
  and after, only the status code. Why: #3458 (PROD-OPS-1 finding 6, same family as #3326).
  Guard: `authorize_lookup_503_test.go` (`TestAuthorizeLookupFault_Is503ThenRecovers`,
  `_SecretRouteIs503`, `_NotFoundProbeIs503`, `_PlainDenialStaysForbidden`,
  `_NonTransientErrorStaysForbidden`, `_RestrictedPATStays403WithoutStorage`,
  `_NotCountedAsForbiddenDenial`; internal/faultstorage on `ResolveUserPermissionAt` /
  `ResolveMachinePermissionAt` / `GetSecret`, red before), gRPC
  `server/grpc/services/authorize_lookup_unavailable_test.go`, the classifier table
  `internal/core/authorize_transient_test.go`, the handler sites
  `server/http/handlers/authorize_outage_handlers_test.go`
  (`TestHandlerPermissionLookupOutageIs503`, `TestHandlerPermissionDenialStays403`,
  `TestHandlerPermissionLookupUnrecognisedErrorStays403`, red on main) with the helper table
  `authorize_unavailable_test.go`, and the family guard
  `authorize_outage_family_guard_test.go`
  (`TestEveryRefusingPermissionCheckMapsAStorageOutage`: an `err != nil || !allowed` branch
  over a permission lookup that refuses 403 / `PermissionDenied` without the transient check
  fails it; it does not see a refusal returned as an error and mapped by a caller, e.g.
  `users_crud.go` `authorizeUserCreationAssignments`).
