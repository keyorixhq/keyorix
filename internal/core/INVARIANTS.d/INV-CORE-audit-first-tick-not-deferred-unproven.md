- **INV-CORE-audit-first-tick-not-deferred-unproven** Server start defers the first
  audit-checkpoint tick behind a fresh signed checkpoint (`AuditCheckpointFirstTickDelay`) only
  when the trusted, signed verification state records a full verification or a rolling cycle in
  progress. A checkpoint alone (an install upgraded from v0.96.x or earlier, which wrote
  checkpoints but no state; or a state that is not trusted) never defers it, because plain
  `audit verify` reads `not_proven` until a cycle completes. Deferring only changes when the work
  runs; it never changes a verdict, so `INV-CORE-audit-verify-never-overclaims` holds unchanged.
  Why: #3743 (a v0.96.3 upgrade read NOT PROVEN for up to 24 h). Guard:
  `TestAuditCheckpointFirstTickDelay`, `TestUpgradeFromV096_AuditVerifyProvenAtFirstTick` and
  `TestUpgradeFromV096_TamperedChainBrokenAtFirstTick` (real v0.96.3 fixture,
  `testdata/upgrade-fixtures/v096-audit`).
