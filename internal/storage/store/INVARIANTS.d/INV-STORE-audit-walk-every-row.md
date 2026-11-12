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

  A purge can also overtake the walk's cursor (remove rows past the batch just read, on a
  chain longer than one batch), or run between the caller's anchor read and the first batch:
  the next row's prev_hash then names a deleted predecessor, or the earliest row is not the
  anchor's. The store walk cannot tell that from a delete outside a purge and stays broken,
  but on exactly those two failures of a chain-start walk it sets `LinkBroken`. Only the core
  layer can authenticate a re-read anchor: `walkAuditChainRacingPurge` (internal/core, used by
  `VerifyAuditChain` and the rolling cycle's chain-start segment) re-reads it and, only if a
  sanctioned purge moved it forward, walks once more from it, re-verifying every surviving row
  and reporting `Reanchored` (whose `PurgedEvents` the checkpoint comparison then uses). An
  anchor that did not move, a failure on the second walk, a pinned segment (`AfterID > 0`)
  and every other failure (a row that does not recompute, a missing entry_hash, rows outside
  the walk) stay broken (#3944). Guard:
  `TestVerifyAuditChain_PurgeOvertakingTheWalkIsMarkedLinkBroken` (and `_Postgres`) and
  internal/core `TestVerifyAuditChain_PurgeOvertakingTheWalkStaysValid` (and `_Postgres`: the
  real `PurgeAuditLogs` inside the walk, with and without a checkpoint certified before it,
  valid; a delete outside a purge and a tamper in the same window, broken).

  The offline verifier (`internal/auditverify`) does not get this rule and keeps
  `held != walked` exact: it reads a quiescent database, see INV-AUDITVERIFY-every-row-walked.
