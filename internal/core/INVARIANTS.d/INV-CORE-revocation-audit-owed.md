- **INV-CORE-revocation-audit-owed** A revocation (role / group-role / permission / role
  delete, group member removal and delete, project member removal, share revoke / self-removal /
  expiry sweep, secret ACL revoke, machine suspend / revoke / token revoke (a rotation's revoke of the old credential
  included) / role removal, PAT and
  session revoke, user suspend / deactivate / delete, SCIM deactivate / deprovision, break-glass
  revoke, JIT role expiry sweep, invitation revoke, access-request withdraw and reject, risk-exception
  revoke, project delete, environment delete, enabling a project's MFA requirement, a role update
  that adds no permission and a share update that widens nothing (`UpdateRole`,
  `UpdateSharePermission`), and the narrowing half of a mixed request, INV-CORE-mixed-request-split)
  is never blocked, delayed or failed by the audit log (Andrei 2026-10-14), and its audit row is
  never silently lost (AUDIT-TX-3, extending INV-CORE-plain-suspend-audit-owed to every revocation).
  The change runs through `withOwedAuditMutation` / `runOwedAuditMutation` (`audit_owed.go`) in ONE
  transaction in which the audit writers, given the owing target, record a `pending_audit_events`
  row instead of appending, so the change and the record of the row it owes commit together. After
  the commit, and after any auth-cache eviction (`settle` is called last: the audit log never
  delays a revocation taking effect), each owed row is appended and its record claimed in one
  transaction with a bounded wait; the first refusal stops the attempts (the rest stay queued and
  are counted). A refused append is loud (`SECURITY:` log, `audit_owed_failures`, the pending
  count in `GET /api/v1/system/info`) and the record stays for `BackfillPendingAuditEvents`. If the
  record itself cannot be written the change still commits (the closure runs again with a
  collect-only target; each owed row is named in a `SECURITY:` line before that commit) and the
  records are written in a transaction of their own right after the commit, before the auth-cache
  eviction and any append wait (`queueOwedRowsLate`, RD-TLA-OWED-FIX-1); the rows are then appended
  and claimed as usual. A crash between the commit and the append loses nothing whenever a record
  of the row committed, with the effect or in that late transaction. It can lose a row only on the
  paths where no record could be written with or after the effect, which the code cannot close
  because the record and the effect cannot commit together there: (i) the process dies after the
  collect-only commit and before the late record commits; (ii) the pending table refuses the late
  record too and the process dies before the direct append; (iii) the event cannot be built at all
  (a panic in the collect-only run, already logged as NOT queued). In (i) and (ii) the row was named
  in the `SECURITY: owed audit event ... commits without its pending record` line written before
  the commit, so the loss is loud, never silent. TLA+:
  `docs/formal/owed-audit/` `pendingfault_fixed.cfg` (`LossOnlyWhereUnrecordable`, `NoSilentLoss`
  pass) and the pre-fix shape as seeded bug `late_after_wait` (`pendingfault_silent.cfg`,
  `bug_late_after_wait.cfg` must fail).
  The "pending-record write fails too" case (`CreatePendingAuditEvent` refused once): the revocation
  still succeeds, the failure is a loud `SECURITY:` log, the late record is written right after the
  commit and the row appended and claimed, so the final state equals an unfaulted run (the audit row
  is written once, nothing is left queued). When the append fails (or is not attempted because an
  earlier row of the same transaction was refused), that record stays pending, so the backfill
  writes it, after a restart too (`TestOwedAudit_RecordAndAppendRefused_RowsSurviveARestart`). If
  the pending table still refuses the late record, the row is appended directly and, when that
  fails, queued late once more (`queueOwedAuditLate`, SUPERFAN-1022 note 1). The only real loss
  without a crash is when that fails too: it is logged as `NOT queued for backfill (record it by
  hand)` and is an audit-trail GAP, not an outcome by design; the fuzz oracle does not accept it (it
  reads as "neither an audit row nor a pending row"). A late record whose commit acknowledgement is
  lost is not claimed against the later attempts, so its row can be written twice (a duplicate,
  never a loss). Direction-dependent operations choose the
  rule from the change itself (`auditedByDirection`: account state into a blocked state and machine
  suspend/revoke are revocations, back to active is a grant that fails closed).
  Why: Andrei 2026-10-14; before AUDIT-TX-3 these wrote a plain best-effort row after the commit
  with no record, so a refused append or a crash lost the row for good.
  Guard: `internal/core` `TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost` (35 kinds x
  success / append error / effect-then-error / panic / crash at the append / pending-record error
  / pending-record panic, SQLite always, PostgreSQL pg-gated; the backfill completes the trail
  exactly once and the chain verifies), `TestUpdateUser_DeactivateAuditInOwnTransaction_NoSQLiteDeadlock`,
  `TestUpdateUser_DeactivateAuditRefused_RowIsOwedAndBackfilled`; the record refused AND a crash at
  the append (35 kinds, `.../pending-record-error+crash-at-audit` in the test above, red before
  RD-TLA-OWED-FIX-1) and `TestOwedAudit_CollectOnlyCommitThenCrash_RowsQueuedBeforeTheAppend` (rows
  queued before the append; with the pending table refusing everything, every row named before the
  commit); `server/faultops`
  `TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed` (35 REST/gRPC ops over the
  router, request still succeeds, rows + pending equals an unfaulted run); the fuzz oracle's
  owed-audit rule `server/faultops` `owed_audit_oracle_test.go` (oracle (a) accepts a success whose
  diff is confined to {AuditEvent, PendingAuditEvent} only for those ops with a fault on
  LogAuditEvent / ClaimPendingAuditEvent, only when every owed audit row has exactly one matching
  pending record, and only when the backfill then converges to the reference exactly; a
  CreatePendingAuditEvent fault must leave the state equal to the reference), calibrated red/green by
  `TestOwedAuditOracle_Calibration` (regression seed `5012b3d0b086d4a4`; `FuzzOwedAuditRevocations` for
  bursts, `TestOwedAuditOracle_SweepEveryScopedOp` for the exhaustive pass and the hand-pinned
  per-op `owedAuditExpectedOwedTypes`; the SSO callback and the SAML ACS are in the rule's scope,
  they share the group and role reconcile in `sso.go`).
  Not covered: `DecideAccessReviewItem`'s revoke keeps its in-tx
  best-effort sink (#2676); a new revocation that does not use `withOwedAuditMutation` is not
  detected by a static guard. The oracle rule cannot show from state alone that the pending record
  committed WITH the effect when an op's catalog scenario revokes nothing visible
  (`POST /users/{id}/revoke-sessions` of a user with no session); there the proof is the exact payload
  match plus the `internal/core` test above. The both-writes-fail gap needs two faults and is not
  reachable by the one-fault fuzzer; it is calibrated by hand (`TestOwedAuditOracle_Calibration`, i2).
  The faultops harness has no kill point, so the record-refused-plus-crash case is driven only in
  `internal/core` (same faultstorage, SQLite always, PostgreSQL pg-gated).
