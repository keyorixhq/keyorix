- **INV-MW-authorize-lookup-error-is-503** When the PERMISSION lookup behind a gate fails
  because storage is unavailable (the request context was canceled or hit its deadline, a
  credential/role lookup was classified transient, or the database connection itself failed:
  `core.IsAuthorizeTransient`, structural `errors.Is`/`errors.As` on sentinels and driver/net
  error types, never message text) the request is REFUSED with 503, `Retry-After` and the
  fixed message "authorization temporarily unavailable, please retry"
  (`authorizeLookupUnavailable`), and over gRPC with `codes.Unavailable` and the same fixed
  message (`authorizeRefusal`), not 403 / `PermissionDenied`: a client retries 503 and does not
  retry a denial. It holds at every place an `AuthorizePrincipal` / `AuthorizeSecret*` /
  `HoldsPermissionInAnyScope` error becomes a refusal (`finishScopedPermissionRequest`,
  `RequirePermissionInAnyScope`, the global-scope probe of `handleScopeResolutionError`, the
  secret fetch of the per-secret gates, and the gRPC `authorizeScoped`, `authorizeScopedTarget`,
  `authorizeSecretScoped`, `authorizeShareScoped`, `CreateSecret`, `ListSecrets`). The handler
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
  `server/grpc/services/authorize_lookup_unavailable_test.go`, and the classifier table
  `internal/core/authorize_transient_test.go`.
