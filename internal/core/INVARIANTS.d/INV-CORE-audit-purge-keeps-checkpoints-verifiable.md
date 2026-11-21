- **INV-CORE-audit-purge-keeps-checkpoints-verifiable** A sanctioned audit retention purge never
  makes the trail fail its checkpoint or high-water checks, and nothing else can borrow that
  allowance: `PurgeAuditLogs` signs the cumulative count of CHAINED rows it removed into the
  retention anchor (layout v2, `retanchor-v2` HMAC, same transaction as the DELETE, previous count
  taken only from an authenticated anchor); checkpoints certify chained + purged; and
  `checkpointTruncationPurged`, `enforceAuditHighWater` and the write-path floor compare chained +
  the authenticated count. An anchor that fails its signature (inflated count, v2→v1 downgrade,
  rewritten without the key) contributes 0. A v1 anchor reads as 0 (pre-#3257 behaviour). A purge
  that removes every chained row (the table empties, or only rows that start at genesis survive)
  signs a restart anchor (#4351): genesis `prev_hash`, empty `entry_hash`, `RowID` the first id it
  did not remove; a row with an id below a restart anchor's `RowID` is BROKEN on both verifiers
  (`checkRestartAnchorBoundary`). A certified head row that is gone is a sanctioned purge only when
  its id is below the authenticated anchor's `RowID` (`checkpointTruncationPurged`, offline
  `enforceCheckpoint`; the incremental tail check then falls back to the full walk); a head row
  that exists must still carry its certified hash. Why: #3257, #4351. Guard:
  `audit_purge_after_checkpoint_test.go`
  (`TestPurgeAfterCheckpoint_VerifyAndCheckpointSucceed`, `_Postgres`, `_RestartedReplicaAgrees`,
  `_SecondPurgeAccumulates`), `audit_purge_after_checkpoint_tamper_test.go` (`_UnsanctionedDeleteBeyondAnchor_Detected`,
  `_TailTruncationWithCheckpointsDeleted_Detected`, `_InflatedPurgedCount_SignatureFails`,
  `_AnchorLayoutDowngrade_SignatureFails`, `_DeleteAndRewriteAnchorWithoutKey_Detected`),
  `store.TestDeleteAuditLogsBefore_PurgedEventsCountsChainedRowsOnly`,
  `store.TestDeleteAuditLogsBefore_EmptiedTableReturnsRestartAnchor` (and `_GenesisSurvivor…`,
  `_EmptiedLegacyOnlyTableNoAnchor`), the offline mirror `auditverify`
  `TestDifferential_PurgeAfterCheckpoint_*`, `auditverify` `TestPurge4351_*` (both cases VALID
  online and offline; no anchor, a changed count, an anchor from another chain and a row below a
  restart anchor BROKEN on both), and `FuzzAuditChainOpSequence`, which runs every purge,
  including emptying ones and ones that remove the latest checkpoint's head. Not covered: a restart
  anchor copied from another deployment signed under the SAME key into a table whose rows were all
  deleted (nothing of the purged chain is left to bind it to; an `--anchor` export held off the
  host still shows it, its head check accepts no purge), and a purge that empties the table
  while an online walk is in progress (the walk can end on fewer rows than the anchor it read
  counts).
