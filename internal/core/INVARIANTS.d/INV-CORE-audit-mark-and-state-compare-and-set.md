- **INV-CORE-audit-mark-and-state-compare-and-set** The audit high-water mark and the signed
  verification state are written only over the stored value the writer read
  (`CompareAndSetSystemMetadata`), never by a last-write-wins upsert, so their monotonicity does
  not rest on `WithAuditCheckpointLock` staying exclusive (a silent lock loss behind a pooler,
  `docs/design/pooler-lock-loss.md` row 15). `advanceAuditHighWater` computes the floor from the
  value it compares against (`auditHighWaterFloorOf`); a lost write re-reads and skips when the
  floor already reaches the checkpoint, retries once otherwise, and writes the host witness only
  after a successful swap. The key-transition re-sign of the mark swaps only over the mark the
  record names. `saveAuditVerifyState` compares against the row the state was loaded from
  (`auditVerifyState.stored`, set by every load and by the key-transition completion and
  accept-loss callers that build a state from a read) and returns `errAuditVerifyStateConflict`
  on a loss; `updateAuditVerifyState` redoes its load-merge-save once, so the change is applied
  on top of the other holder's row. So a slower holder never puts a lower mark back over a higher
  one, and never drops a failure the other holder recorded. Why: AUDIT-HIGHWATER-CAS-1.
  Guard: `TestAuditHighWaterCAS_SlowerHolderNeverLowersTheMark`,
  `TestAuditVerifyStateCAS_LostUpdateKeepsRecordedFailure` (`internal/core`, two cores on
  separate pools, SQLite and PostgreSQL), `TestCompareAndSetSystemMetadata`
  (`internal/storage/store`). Not covered: `admin audit accept-loss` writes its mark with an
  upsert (it runs only under the exclusive database lock with the server stopped); a DB-level
  actor who rewrites either row is ADR-029's residual, covered by the signatures and the trail.
