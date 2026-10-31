- **INV-STORE-audit-walk-every-row** `VerifyAuditChainSegment` (and so `VerifyAuditChain`) is
  not valid unless it visited every `audit_events` row in its range. The keyset walk
  (`id > lastID`) never visits an id 0 row (SQLite `INTEGER PRIMARY KEY` and PostgreSQL
  `bigserial` both accept an explicit `id = 0`), a NULL id, or a second row under an id a batch
  ended on (a schema edited to drop the primary key). So after the walk, one COUNT (per walk,
  not per batch) of the rows it should have visited must equal the rows it did visit:
  - from the chain start, `id IS NULL OR id <= lastID`;
  - for a pinned segment, `id > AfterID AND id <= lastID`.

  Otherwise the walk reads broken ("outside the chain"). This is the online twin of
  INV-AUDITVERIFY-every-row-walked. Why: #3808. Guard:
  `TestVerifyAuditChain_RowsOutsideTheWalkAreNotValid` (SQLite: id 0, id 0 on an empty chain,
  NULL id, duplicate id on a batch boundary, a pinned segment, and an intact chain staying
  valid), `TestVerifyAuditChain_IDZeroRowNotValid_Postgres` (pg-gated),
  `internal/auditverify` `TestDifferential_TamperMatrix` ("forged row inserted with id 0") and
  `TestReviewAV_RowsOutsideTheWalkAreBroken` (online agrees).
