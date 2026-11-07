- **INV-CORE-render-check-fault-reads-as-ref-not-found** When the per-reference permission
  check in `stageRenderRef` cannot be evaluated (a storage read fault, or a transient RBAC
  lookup failure the check folds into a denial, seen through `AuthorizeFaultRecorder`), the
  refusal is a `secretRefCheckFault`: it renders as and matches (`errors.Is`) only
  `ErrSecretRefNotFound`, never `ErrStorageReadUnavailable`, so every mapper that does not ask
  answers it exactly like a missing or forbidden reference (#181). Only a transport that has
  established the caller may tell "missing" from "forbidden" (the render handler's global
  `secrets.read` holder) asks with `SecretRefCheckFault` and answers 503. The denial is audited
  `internal_error`. Why: the fault only happens for a secret that exists, so a generic 503
  would be an existence oracle during a partial outage (CORE-FAULT-TAILS-1).
  Guard: `secret_render_check_fault_test.go` `TestRenderSecretTemplate_PermissionCheckFaultIsNotAVerdict`;
  server/http/handlers `TestRenderTemplate_PermissionCheckFaultIs503ForGlobalHolder`,
  `TestRenderTemplate_PermissionLookupOutageIsNoExistenceOracle`.
  **Not covered**: a non-transient RBAC lookup error stays a plain denial (fail closed, as in
  `checkSecretPermission`); the check's own cost still varies by grant branch (#G10 residual).
