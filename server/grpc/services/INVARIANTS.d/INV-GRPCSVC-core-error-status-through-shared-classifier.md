- **INV-GRPCSVC-core-error-status-through-shared-classifier** A service turns a core or storage
  error into a status through the shared classifier (`server/errclass`, the same closed class
  set the REST handlers use) and its gRPC adapter `coreErrorStatus`
  (server/grpc/services/core_error_status.go): `InvalidArgument`, `NotFound`, `AlreadyExists`
  (conflict), `FailedPrecondition` (target state), `PermissionDenied`, `Unavailable` with the
  `storage_unavailable` / `audit_unavailable` ErrorInfo (the existing shapes), `Internal` with a
  fixed text and the cause logged (`internalFailure`). REST renders the same class table through
  `answerCoreError` (`INV-HTTP-core-error-answered-through-shared-classifier`), so a sentinel
  can no longer be 404 on REST and `Internal` over gRPC (#4020's class) or `Unavailable` on one
  transport and a verdict on the other (#3911's class). gRPC texts are fixed per class or passed
  by the site (never a driver message, a state name or caller input: GRPC-003/004). A permission
  refusal reached through a recorded transient lookup fault is `Unavailable` with the gates'
  fixed text (`authorizeRefusal`), as `mapSecretMutationError` already did. The family mappers
  (`mapRoleError`, `mapMachineError`, `mapUserError`, `mapProjectError`, `mapShareError`,
  `mapDynamicError`, `mapSecretACLError`, `mapSecretError`, `groupError`) are not yet callers of
  the adapter; they migrate one family per PR, `mapRoleError` and `authorizeShareScoped` after
  #4147 (GRPC-OUTAGE-TAILS-1) merges. Guard: `TestCoreErrorStatus_EverySentinelRendersItsClass`,
  `TestCoreErrorStatus_TextsAndDetails` (every table row and the ErrorInfo details), the REST
  twin `TestAnswerCoreError_EverySentinelRendersItsClass` over the same `errclass.Sentinels()`
  (the parity check), and the family guard `TestEveryGrantingServiceMapsPermissionDenied` (every
  service method calling a granting core method, read from
  `internal/core/testdata/grant_ceiling_reaching_methods.txt`, hands the error to a mapper that classifies `ErrPermissionDenied`; report-only on pull
  requests while its `docs/guard-rollout.d` row exists).
