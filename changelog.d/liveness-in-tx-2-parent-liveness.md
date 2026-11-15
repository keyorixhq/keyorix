### Testing
- **The expiry sweep revokes a lease under a deleted project (#2652).** New test
  `TestDynamicSecrets_SweepRevokesLeaseUnderDeletedProject` shows that `RevokeExpiredLeases`
  revokes an expired `active` or `revoke_failed` lease whose config the #369 cascade
  disabled and whose project and environment were soft-deleted. That bounds any lease that
  escapes `DeleteProject`'s own revocation to its TTL. Invariant
  `INV-CORE-expired-lease-revoked-under-deleted-parent` says parent liveness gates minting,
  never revocation.
- **Child-parent liveness ledger updated.** Four rows in
  `docs/child-parent-liveness-exempt.tsv` (CreateEnvironment, CreateSecret, and two
  RestoreProject rows) were still marked `UNSAFE-OPEN` after #2710, #2711 and #2724 had been
  fixed. They are now `SERIALIZED` and name the Postgres test that proves each one. The fifth
  row, RestoreProject vs DeleteEnvironment, was not covered by #2724's fix; it now points at
  #4287 and says why it is not reachable through the API today.
