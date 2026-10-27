- **INV-CORE-audit-seal-never-valid-tamper-broken** An accepted audit loss (`admin audit
  accept-loss`, `audit_seal.go`, `audit_seal_accept.go`) is written only by
  `AcceptAuditLoss` after `PlanAuditLossAcceptance` proved a loss at exactly the named ids:
  a gap whose first surviving row recomputes and whose prev_hash names a row that is gone
  (not the row before, not an inserted one), or a tail truncation whose certified head is
  missing and whose count fell. It refuses a modified row, the pre-#1452 encoding, a key
  mismatch, an unauthenticated checkpoint, high-water mark or retention anchor, an untrusted
  state, a discontinuity of another kind and an untrusted earlier seal. The record
  (`audit_seals`) is MACed with the checkpoint key under its own domain, hash-linked (`seq`,
  `prev`), and named by one in-chain `system.audit_loss_accepted` event. A sealed chain is
  reported `sealed`, never `valid`, on every view (incremental, full, job, posture). The walk
  steps over a sealed gap only at the exact last-good and resume rows (and hashes) it names.
  Checkpoints and the high-water mark written after a seal sign the v2 canonical form bound to
  the seal count and newest digest. The state counts its seals. So a deleted, altered, moved,
  replayed or incomplete seal, a removed event, a row removed or put back around the gap, or
  a state from another seal segment reads broken. Key changes carry the record (the
  transition names its digest, completion re-signs it first). `recover-admin` never seals.
  The writes go record, event, checkpoint and high-water mark, state; an acceptance stopped
  after any of them reads broken until a re-run of the command completes it, which first
  checks the chain still holds what the seal recorded as surviving.
  Why: AUDIT-ACCEPT-LOSS-1, constraints 1-8 of docs/design/recovery-options.md §2. Guard:
  `TestAuditSeal_*` (`internal/core`, SQLite and PostgreSQL; `_CrashAtEveryStepResumes`,
  `_DeletedSealKeepsStatePin`), `TestSealDifferential_*`
  (`internal/auditverify`), `TestPerformRecoverAdmin_NeverSealsALoss`,
  `TestAcceptLoss_RequiresConfirmThenSeals`, `scripts/drills/accept-loss.sh`. Not covered: a
  verification state discontinuity with an intact chain cannot be accepted (it stays
  sticky), and a holder of the checkpoint key can seal anything this command would accept.
