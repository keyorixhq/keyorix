- **INV-MW-scope-resolver-read-fault-is-503-for-global-holders** Every scope resolver that READS its
  target (`ScopeFromEnvParam`, `ScopeFromSecretParam`, `ScopeFromDeletedSecretParam`, both reads of
  `ScopeFromShareParam`, `ScopeFromRotationPolicyParam`, `ScopeFromDynamicSecretConfigParam`,
  `ScopeFromDynamicSecretLeaseParam`) and the secret fetch of `RequireScopedSecretPermission` tell a
  read FAULT from a positive not-found with `core.ReadFault`: a fault returns `errTargetReadFault`
  (wrapping `core.ErrStorageReadUnavailable`), and `handleScopeResolutionError` answers it exactly as
  INV-MW-lease-scope-read-fault-is-503-for-global-holders says: 503 `storage_unavailable` +
  `Retry-After` for a caller who holds the permission at global scope, the same 403 an absent target
  gets for anyone else, and the shared 503 "authorization temporarily unavailable" for every caller
  when the cause is transient. A positive not-found is unchanged (404 for a global holder, 403
  otherwise, same body). The driver cause is logged, never sent. Why: the resolvers folded every read
  error into `errTargetNotFound`, so during an outage a global holder was told the target did not
  exist while the operation was never applied (STORAGE-ERR-CLASS-3). Guard:
  `scope_resolver_read_fault_test.go` (`TestScopeResolverReadFault_*`, internal/faultstorage on each
  target read, red before) and the source scan `TestNoStorageReadErrorFoldedIntoNotFound`, which also reads server/middleware/auth.go
  (internal/core/guards). **Not covered**: `RequireScopedSecretRefPermission` (core
  `ResolveSecretRef` folds the `GetSecretByName` read into `ErrSecretRefNotFound`), and the gRPC
  `authorizeScopedTarget` callers.
