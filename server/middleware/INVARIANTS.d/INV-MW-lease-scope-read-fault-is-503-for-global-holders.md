- **INV-MW-lease-scope-read-fault-is-503-for-global-holders** When `ScopeFromDynamicSecretLeaseParam`
  cannot READ the lease (a storage fault, as opposed to finding no such row), `handleScopeResolutionError`
  answers a caller who holds the permission at global scope 503 `storage_unavailable` with
  `Retry-After`, and a caller without global standing the same 403 an absent lease gets, so a fault
  adds no existence signal for them. That split holds for a non-transient fault only: a transient
  cause (connection refused/reset, a driver timeout, a cancelled context; `core.IsAuthorizeTransient`)
  stays wrapped in `errTargetReadFault` and is answered first by `authorizeLookupUnavailable`, so EVERY
  caller, holder or not, gets the same 503 "authorization temporarily unavailable"
  (INV-MW-authorize-lookup-error-is-503); the outage hits every target alike, so that is no existence
  signal either. A positive not-found is unchanged (404 for a global holder, 403
  otherwise). The fault is `errTargetReadFault`, wrapping `core.ErrStorageReadUnavailable`; it is
  audited as an internal-error read denial, and the driver cause is logged, never sent. Why: the
  resolver folded every read error into "target not found", so during an outage a global holder was
  told the lease did not exist while the revoke or renew was never applied (STORAGE-ERR-CLASS-2).
  Guard: `TestDynamicSecretLeaseRoutes_ReadFaultIs503ForGlobalHolders` (server/http, real router;
  covers both the non-transient and the transient case).
  The other scope resolvers follow the same rule since STORAGE-ERR-CLASS-3
  (INV-MW-scope-resolver-read-fault-is-503-for-global-holders).
