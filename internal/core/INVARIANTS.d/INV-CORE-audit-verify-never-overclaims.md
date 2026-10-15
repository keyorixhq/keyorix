- **INV-CORE-audit-verify-never-overclaims** Incremental audit-chain verification
  (docs/specs/audit-incremental-verification.md) moves the full re-hash of every row off the
  request path and off startup without dropping it, and never reports `valid` for rows it has
  not verified. `VerifyAuditChain` and `WriteAuditCheckpoint` keep their full-walk semantics.
  The scheduler tick and the on-demand checkpoint extend the latest signed checkpoint with a
  tail check that pins the certified head row (stored hash and recompute), and they refuse
  while a failure is recorded. A rolling cycle re-walks the whole chain in seeded segments
  that end on a signed checkpoint head, so every row is re-hashed at least once per cycle.
  Progress, the last full result and a sticky failure live in one HMAC-signed state row
  (domain-separated; a row that is absent, forged or unverifiable is ignored and reads as
  `not_proven`). The API, posture and gRPC report `valid` only when the tail check passed
  AND a full verification completed within two cycles with no failure recorded. Why: AUDIT-SCALE-1
  §4.3 (full walks failed over HTTP from about 2.5M rows). Guard: `audit_verify_incremental_test.go`
  (`TestIncrementalVerify_NotProvenUntilFirstCycleCompletes`, `_TailTamperCaughtAtNextTick`,
  `_OldSegmentTamperCaughtWithinOneCycle`, `_RehashBelowCheckpointHeadCaughtWithinOneCycle`,
  `_RehashThroughCheckpointHeadCaughtImmediately`, `_HeadRowContentEditCaughtImmediately`,
  `_TailTruncationWithNewerCheckpointsDeleted`, `_ForgedStateIgnored`,
  `_TickAndPostureNeverWalkTheWholeChain`, `_FullJob`), `_Postgres`, and
  `store.TestVerifyAuditChainSegment_*`. Not covered: replay of an older signed state row
  (the rows stay broken, so the next cycle re-detects them; the
  `system.audit_chain_verification_failed` event in the chain is the durable record).
