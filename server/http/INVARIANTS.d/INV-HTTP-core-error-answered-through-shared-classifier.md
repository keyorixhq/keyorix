- **INV-HTTP-core-error-answered-through-shared-classifier** A handler turns a core or storage
  error into an HTTP answer through the shared classifier (`server/errclass`: one sentinel→class
  table with the closed set invalid input 400, not found 404, conflict 409, precondition 409,
  permission denied 403, unavailable 503 + `Retry-After`, audit unavailable 503, internal 500) and
  its REST adapter `answerCoreError` (server/http/handlers/core_error_answer.go), passing only
  the route's client texts; the gRPC services render the same table through `coreErrorStatus`
  (`INV-GRPCSVC-core-error-status-through-shared-classifier`), so the two transports agree on
  every sentinel by construction. A per-handler switch that classifies by message text, or that
  ends in `default: 500` for a typed refusal, is the defect class of #4132 (nine handler families
  answered a core refusal with an undeclared 500) and #3979 (one grant route answered the
  ceiling refusal 500 while its sibling answered 403). Order inside the adapter: partial
  mutation, audit outage, storage read fault, a permission refusal reached through a recorded
  transient lookup fault (`core.WithAuthorizeFaultRecorder`; `OfMutation`), then the class. The
  classifier never widens who is allowed: every class is a refusal; only status and text change.
  A text that merely says "not found" / "permission denied" / "already exists" is Internal
  (`TestOf_TextIsNotAClass`). Migrated so far: the #4132 families (machine tokens, resume,
  project stats, templates, rejection templates, folders, certificate, access history,
  access-review revoke/attest), the five in-core-authorized secret mutations (#3873, with the
  fault recorder), and `sendMachineRefusal` (classifier-backed texts). Not yet migrated (the
  per-family mappers keep working; move them one family per PR): `catalog.go` project CRUD,
  `rbac.go`, `invitations.go` (AUTHZDIFF-TAILS-1's files), `shares_crud.go`, `groups_handler.go`,
  `risk_exceptions.go`, `secret_acl_handler.go`, `secrets_versions.go`, SCIM (RFC 7644 bodies by
  design), the login / MFA / impersonation lane (FIX-3277). Guard:
  `TestClassTablesAgree`, `TestOf_EverySentinelClassifiesWrapped`, `TestOf_TextIsNotAClass`,
  `TestOf_Priority` (server/errclass); `TestAnswerCoreError_EverySentinelRendersItsClass` and the
  gRPC `TestCoreErrorStatus_EverySentinelRendersItsClass` (every table row through each
  adapter: the REST/gRPC parity check on the sentinel errors);
  `TestErrMap_StatefulFindingsAnswerDeclaredStatus` (the #4132 findings, en + pseudo-locale);
  `TestSecretMutation_PermissionLookupOutageIs503` and faultops
  `TestLookupVerdict_SecretMutationPermissionFaultIs503` (#3873). Not covered: a handler that
  calls a granting core method and does not map `ErrPermissionDenied` (the #3979 family) has no
  REST guard in this tree yet; it lands with #4165 (`TestEveryGrantingHandlerMapsTheCeilingRefusal`).
  The gRPC twin is `TestEveryGrantingServiceMapsPermissionDenied`
  (`INV-GRPCSVC-core-error-status-through-shared-classifier`). A handler that classifies by text
  and never calls a granting method is caught only when its family migrates
  (`INV-HTTP-classify-errors-by-sentinel-not-text` lists the state).
