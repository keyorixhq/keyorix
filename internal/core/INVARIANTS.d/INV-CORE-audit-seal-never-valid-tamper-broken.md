- **INV-CORE-audit-seal-never-valid-tamper-broken** An accepted audit loss (`admin audit
  accept-loss`, `audit_seal.go`, `audit_seal_accept.go`) is written only by
  `AcceptAuditLoss` after `PlanAuditLossAcceptance` proved a loss at exactly the named ids:
  a gap whose first surviving row recomputes and whose prev_hash names a row that is gone
  (not the row before, not an inserted one), or a tail truncation whose certified head is
  missing and whose count fell. It refuses a modified row where signed evidence shows one
  (#3802):
  - a resume row that does not recompute;
  - a break with no id missing between the last good row and the resume row;
  - a `Before` signed past the gap's last good row that counts every surviving row
    (measured loss 0);
  - any surviving row whose hash differs from what an authenticated pin certified. The pins
    are every `audit_checkpoints` row that authenticates under the current key and some seal
    prefix, the high-water mark, the retention anchor, the state's pin, last tail check and
    rolling cycle, the witness, earlier seal records, and a verified anchor
    (`auditLossCheckPins`).

  Surviving rows before a break that no pin covers are named in the plan and recorded in the
  seal's `unpinned` spans, never silently accepted. It also refuses the pre-#1452 encoding, a
  key mismatch, an unauthenticated checkpoint, high-water mark or retention anchor, an untrusted
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
  after any of them reads broken until a re-run of the command completes it. The re-run writes
  nothing unless the request names the unfinished record's digest (`--resume-seal`, #3803;
  `AcceptAuditLoss` refuses a resume plan made without it), so `--confirm` alone never
  completes a record the operator did not read; the apply re-checks under the lock that the
  unfinished record is still the one that digest names, and refuses another record swapped in
  since the plan (`TestAuditSeal_ResumeRefusesSwappedUnfinishedRecord`). Completing it first
  checks the chain still holds what the seal recorded as surviving and everything the latest
  checkpoint, the high-water mark, the state's pin and the host's high-water witness file
  (SQLite) signed under the current seals certify (a post-seal truncation is refused, never
  completed over, even when every database row was rolled back to a pre-acceptance copy). A
  witness that exists but is not a regular file, does not parse or authenticates under neither
  binding is refused, and the re-seal never lowers a witness signed under the current seals. It skips only its own
  half-written artifacts (a checkpoint or mark signed under the seals before it): one that
  authenticates under neither, or a mark missing although the seal recorded a certification,
  is refused, not read as "no certification". After a key change (#3814) an artifact still
  signed under the previous key counts, or is skipped, only when the active key transition
  record, MACed by both keys, names its exact digest with the binding the prepare (holding
  the old key) authenticated it under (`auditKeyTransitionSealing`, `audit_seal_key_change.go`;
  the naming is tied to the newest seal's number and digest and followed through a chain of
  key changes); a witness counts that way only when it mirrors a mark so named under the seal.
  Nothing the record does not name is accepted on the new key's behalf, and the record names
  nothing that authenticated under no seal binding. It refuses ids other than the seal's own, and
  keeps any discontinuity or failure the state carries in its accepted list; its plan names
  when, by whom and why the seal was recorded. A first acceptance refuses a missing mark beside
  a signed checkpoint, and an operator name or reason with a control or format character, a
  line or paragraph separator, or over its length limit. A first acceptance counts the host
  witness in `Before` when it authenticates under the seals before it, prints it in the plan
  with the fact that confirming lowers it, refuses a damaged witness, one that claims the current
  key version without authenticating under it (garbled or replaced; only one under another key
  version is a pre-key-change witness that is replaced), and one that authenticates
  under a seal list the database does not hold (a rollback of the seal record), and refuses a
  `Before` whose head is gone unless that head is named as the truncation. Before writing the
  record, and again in the re-seal, the witness is lowered only from the seals before the
  newest one and only as far as the record's `Before` names (`auditWitnessLowerProblem`, which
  refuses the garbled current-key witness too; on a resume its refusal names the way out:
  compare with an off-host anchor, then move the witness aside, since re-running cannot change
  the record).
  Why: AUDIT-ACCEPT-LOSS-1, constraints 1-8 of docs/design/recovery-options.md §2. Guard:
  `TestAuditSeal_*` (`internal/core`, SQLite and PostgreSQL; `_CrashAtEveryStepResumes`,
  `_DeletedSealKeepsStatePin`,
  `_ResumeRefusesPostSealTruncation`, `_ResumeRefusesOtherIDs`,
  `_ResumeRefusesRemovedCertifications`, `_ResumeRefusesRemovedCertificationsUncertifiedSeal`,
  `_ResumeRefusesUnaccountedArtifacts`, `_ResumeRefusesRollbackBelowWitness`,
  `_ResumeRefusesUnreadableWitness`, `_CrashAtEveryStepResumesWithWitness`,
  `_ResealKeepsHigherWitness`, `_RefusesMissingHighWater`,
  `_RefusesUnsafeOperatorText`, `_WitnessAboveDatabaseCountsInPlan`,
  `_ApplyRefusesUnnamedHigherWitness`, `_WitnessUnderRolledBackSealRefused`,
  `_ResumeAfterKeyChange`, `_ResumeAfterTwoKeyChanges`, `_ResumeAfterKeyChangeRefusesUnaccounted`,
  `_GarbledCurrentKeyWitnessRefused`, `_ResumeRefusalNamesWitnessWayOut`,
  `_ResumeWithoutDigestWritesNothing`, `_ResumeNeedsRecordDigest`, `_ResumeSealWithoutPendingRefused`,
  `_PrefixRewriteBeforeLossRefused`, `_RewrittenRowNoIDMissingRefused`, `_RewriteOverIDHoleRefused`,
  `_GenuineDeletionPinnedPrefixSeals`, `_UnpinnedPrefixRecorded`),
  `TestSealDifferential_*`
  (`internal/auditverify`), `TestPerformRecoverAdmin_NeverSealsALoss`,
  `TestAcceptLoss_RequiresConfirmThenSeals`, `TestAcceptLoss_ResumeNeedsResumeSeal`, `scripts/drills/accept-loss.sh`. Not covered: a
  verification state discontinuity with an intact chain cannot be accepted (it stays
  sticky), and a holder of the checkpoint key can seal anything this command would accept. A
  whole-trail rollback (every row, the seal record, checkpoints, mark and state put back to an
  earlier copy) is caught only by evidence the copy does not contain: on SQLite the intact host
  witness refuses a resume over cut certified rows and a new acceptance after the seal record
  was rolled away; on PostgreSQL, or when the witness was rolled back or deleted with the
  database (an absent witness reads as none), a rollback to part way through an acceptance reads
  as an unfinished acceptance and one to before it as a fresh loss. Only an off-host
  `export-checkpoint` anchor (`--anchor`; one bound to a seal the database no longer holds does
  not authenticate) or the operator, warned by the resume plan, tells them apart
  (docs/operator/audit-chain-break-runbook.md §8). Rows written after the last checkpoint were
  never certified and are not detected by anything. A rewrite of rows before a gap that no pin
  covers (including one whose older checkpoints were deleted with it: only the latest is
  guarded by the high-water mark) is recorded as unpinned, not refused.
