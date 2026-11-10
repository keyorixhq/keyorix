- **INV-STORE-audit-walk-every-row** `VerifyAuditChainSegment` (and so `VerifyAuditChain`) is
  not valid unless it visited every `audit_events` row in its range. The keyset walk
  (`id > lastID`) never visits an id 0 row (SQLite `INTEGER PRIMARY KEY` and PostgreSQL
  `bigserial` both accept an explicit `id = 0`), a NULL id, or a second row under an id a batch
  ended on (a schema edited to drop the primary key). So after the walk, one COUNT (per walk,
  not per batch) of the rows it should have visited must not exceed the rows it did visit (a
  retention purge landing after the walk can only lower it, #3944):
  - from the chain start, `id IS NULL OR id <= lastID`;
  - for a pinned segment (the incremental request-time tail check and every rolling-cycle
    segment after the first), `id IS NULL OR id < 1 OR (id >= AfterID AND id <= lastID)`,
    which must not exceed the rows walked plus the seed row. Counting only the rows after the seed
    left an id 0 row reading valid on GET /audit/verify and gRPC VerifyAuditChain until the
    rolling cycle next walked from the chain start, and a second row under the seed's id
    outside every walk (AUDIT-VERIFY-ONLINE-1).

  Otherwise the walk reads broken ("outside the chain"). `MigrateAuditChainEncoding`'s
  pre-flight walk makes the same count from the chain start and refuses to re-encode on any
  mismatch, a deficit included: it excludes the retention purge (the same advisory lock on
  PostgreSQL, one transaction on SQLite), so a lower count there is an unsanctioned delete. This is the online twin of
  INV-AUDITVERIFY-every-row-walked. Why: #3808. Guard:
  `TestVerifyAuditChain_RowsOutsideTheWalkAreNotValid` (SQLite: id 0, id 0 on an empty chain,
  NULL id, duplicate id on a batch boundary, a pinned segment, and an intact chain staying
  valid), `TestVerifyAuditChainSegment_RowsNoWalkReachesAreNotValid` (pinned segments: id 0,
  a negative id, NULL id, a second row under the seed's id),
  `TestMigrateAuditChainEncoding_RefusesRowsOutsideTheWalk`,
  `TestVerifyAuditChain_PurgeBetweenWalkAndCountStaysValid` (and `_Postgres`),
  `TestVerifyAuditChain_RowsOutsideTheWalkOutnumberingAPurgeStayBroken`,
  `TestMigrateAuditChainEncoding_PreflightCountRefusesDeletes` (and `_Postgres`),
  `TestVerifyAuditChain_IDZeroRowNotValid_Postgres` and
  `TestVerifyAuditChainSegment_IDZeroRowNotValid_Postgres` (pg-gated), internal/core
  `TestIncrementalVerify_IDZeroRowCaughtByNextRequest` (and `_Postgres`),
  `internal/auditverify` `TestDifferential_TamperMatrix` ("forged row inserted with id 0") and
  `TestReviewAV_RowsOutsideTheWalkAreBroken` (online agrees).
