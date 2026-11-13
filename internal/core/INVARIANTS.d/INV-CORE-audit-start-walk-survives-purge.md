- **INV-CORE-audit-start-walk-survives-purge** Every online walk of the audit chain from its
  start (seeded from the retention anchor, `AfterID == 0`) goes through
  `walkAuditChainRacingPurge`, and a verdict or write that counts purged events takes the
  count from the anchor the walk ended on (`Reanchored` when set). A retention purge holds
  no lock a walk holds, so one that removes rows past the walk's cursor would otherwise read
  a valid chain BROKEN (`VerifyAuditChain`, the rolling cycle) or refuse it (the checkpoint
  write, the accept-loss re-seal). A delete outside a purge, a tamper, or an anchor that did
  not move keeps the broken verdict. Why: #3944, AUDIT-WALK-TAILS-1. Guard:
  `TestEveryPlainAuditWalkIsAllowlisted` (internal/core/guards, every plain
  `walkAuditChain`/`walkAuditChainGaps`/storage-walk call site is allowlisted with its reason;
  calibration `TestAuditWalkRacingPurgeGuard_RejectsAPlainWalker`), and
  `TestVerifyAuditChain_PurgeOvertakingTheWalkStaysValid`,
  `TestWriteAuditCheckpoint_PurgeOvertakingTheWalkStillWrites`,
  `TestAcceptAuditLoss_PurgeOvertakingTheResealWalkStillSeals` (each also `_Postgres`,
  pg-gated). Not covered: the tail walk from a checkpoint head (`auditTailCheck`) is not a
  start walk and is allowlisted as such; a purge that reaches past that head during the tail
  walk is not exercised by these tests.
