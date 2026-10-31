- **INV-MW-lease-scope-read-fault-is-503-for-global-holders** When `ScopeFromDynamicSecretLeaseParam`
  cannot READ the lease (a storage fault, as opposed to finding no such row), `handleScopeResolutionError`
  answers a caller who holds the permission at global scope 503 `storage_unavailable` with
  `Retry-After`, and a caller without global standing the same 403 an absent lease gets, so a fault
  adds no existence signal for them. A positive not-found is unchanged (404 for a global holder, 403
  otherwise). The fault is `errTargetReadFault`, wrapping `core.ErrStorageReadUnavailable`; it is
  audited as an internal-error read denial, and the driver cause is logged, never sent. Why: the
  resolver folded every read error into "target not found", so during an outage a global holder was
  told the lease did not exist while the revoke or renew was never applied (STORAGE-ERR-CLASS-2).
  Guard: `TestDynamicSecretLeaseRoutes_ReadFaultIs503ForGlobalHolders` (server/http, real router).
  **Not covered**: the other scope resolvers (config, share, rotation policy, secret, ...), which
  still fold a read fault into `errTargetNotFound`.
