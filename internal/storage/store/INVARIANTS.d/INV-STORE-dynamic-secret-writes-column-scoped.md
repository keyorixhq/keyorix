- **INV-STORE-dynamic-secret-writes-column-scoped** No production code writes a
  `dynamic_secret_configs` or `dynamic_secret_leases` row in full. `classification` moves
  only through `SetDynamicSecretConfigClassification` (CAS on the value the caller read),
  `expires_at` only through `ExtendDynamicSecretLeaseExpiry` (`WHERE lease_id = ? AND
  status = 'active'`, so a renewal cannot reach a revoked lease), and the revocation
  columns only through `RecordDynamicSecretLeaseRevocation` (deliberately
  unconditional — it records what already happened at the backend, so it must land
  whatever else moved; a lease whose target drop failed must never be left reading
  `active`). Why: #2698 — the bare `Save`s these replace wrote `disabled=false` back over
  the incident kill switch (`SetDynamicSecretConfigEnabled(false)`, which also revokes
  the config's live leases) so `IssueLease` minted real database credentials again with
  no audit record of the re-enable, and wrote a lease's stale `Status`/`RevokeError`/
  `RevokedAt` back over a successful `RevokeLease` — reviving it as `active` with a later
  expiry, holding a `MaxActiveLeases` slot, on backends where `engine.Renew` is a no-op
  so nothing downstream would notice. Note `ExtendDynamicSecretLeaseExpiry` normalises
  `expires_at` to UTC itself: a raw `Updates` bypasses `DynamicSecretLease.BeforeSave`,
  which exists for `ListExpiredActiveLeases`' SQL range query (G81, see
  INV-STORE-19). Guard: `internal/core` `TestUpdateDynamicSecretLease_HasNoProductionCaller`
  (a derived repo sweep, failing both on a new caller and on a stale allowance) and
  `TestDynamicSecretWrites_AreColumnScoped` (structural), plus
  `TestCTAReview_ClassifyDynamicSecretConfig_vs_KillSwitch_CrossReplicaPostgres` and
  `TestCTAReview_RenewLease_vs_RevokeLease_CrossReplicaPostgres` (pg-gated).
