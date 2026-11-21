- **INV-STORAGE-upgrade-audit-intact** An upgrade loses no `audit_events` row, and the hash chain
  still verifies from every source already on HEAD's encoding (v0.92.1 and later). Why: the audit log
  is evidence, and a migration that rewrites or rebuilds its table can break it without any error.
  Guard: `internal/storage` `FuzzUpgradeFromOldSchema`, `FuzzUpgradeInterrupted`, red-proved by
  `TestUpgradeOracles_RedProof/invariant3_*`. **Not covered**: v0.91.0 gets the row count only, its
  chain predates the #1452 encoding and needs the operator's migrate-chain-encoding step.
