- **INV-STORE-audit-linked-flight** On PostgreSQL a flusher batch whose chain head the flusher
  does not know (head cache not armed, or a one-flight attempt that provably wrote nothing) and
  that fits one INSERT goes as ONE linked flight (`runAuditLinked`): BEGIN, the fast-mode
  `SET LOCAL` (only when enabled), `pg_advisory_xact_lock(KEYAUDIT)`, one statement
  (`auditLinkedSQL`) that reads the id-DESC head in its own snapshot (taken after the lock), links
  rows 1..n onto it with `entry_hash = encode(sha256(field(prev) || suffix), 'hex')` where suffix is
  `auditEntryHashSuffix` computed in Go (the one encoding `computeAuditEntryHash` and
  `VerifyAuditChain` use; an unchained or absent head links to genesis), inserts GORM's VALUES in
  batch order and raises unless the stored rows are exactly the n rows, all above the head,
  linked prev_hash -> entry_hash in id order (the raise never degrades to NULL); then the
  access-log INSERT and COMMIT. Four rules hold. (1) KEYAUDIT is never held across a client round
  trip on this path. (2) After COMMIT every stored entry_hash is recomputed in Go
  (`crossCheckAuditLinked`); a mismatch fails every item of the batch WITHOUT a retry or bisection
  (`errAuditLinkedHashMismatch` in `finishAuditBatch`: the rows are already stored, a retry would
  append them twice), logs a SECURITY line and turns linking off for the process
  (`auditLinkedOff`). (3) A batch that cannot be linked (too large for one INSERT, an unexpected
  GORM statement shape, no column type) and a linked attempt that provably wrote nothing take the
  two-flight path (`runAuditPipeline`) on a connection taken afresh (the failed transaction is
  rolled back first). (4) The flusher never asks the pool for a second connection: the column
  types for the casts are read once per store on the flight's own connection. The armed
  one-flight commit and the pipelined batches are unchanged, and the chain bytes are those of
  the two-flight path for the same input. Why: PERF-MULTINODE-1 — with two or more nodes every
  batch took two flights and KEYAUDIT, which every node's appends queue on, was held across the
  round trip between them.
  Guard: `internal/storage/store` `TestLinkedFlight_PostgresHashesMatchGo` (genesis, onto a head,
  onto an unchained legacy row; same rows as the two-flight path; red with the SQL encoding
  changed), `TestLinkedFlight_PostgresThreeReplicasConcurrent`,
  `TestLinkedFlight_PostgresTwoReplicasAlternate` (a miss's retry is one flight),
  `TestLinkedFlight_PostgresOutOfOrderIDsFailClosed` (red with the in-statement check removed),
  `TestLinkedFlight_PostgresHashMismatchFailsClosedOnce`, `TestLinkedFlight_PostgresRunsFromGenericPlans`,
  `TestCommitBatchAttempt_PostgresFlightCount` (all pg-gated), `TestLinkedAuditInsert_Shape`.
  **Not covered**: as for the other paths, a writer that inserts into audit_events without taking
  KEYAUDIT can race the head read; and a hash mismatch is detected only after COMMIT, so the
  batch's rows stay stored (VerifyAuditChain reports them) although none of its reads is answered.
