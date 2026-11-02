- **INV-CORE-audit-verify-state-never-silently-restarts** Audit verification never
  starts over from whatever state row it finds. A row that is deleted (while the chain
  holds a `system.audit_verification_state_initialized` marker or a discontinuity event,
  while this process already read one, or while the latest checkpoint or high-water mark
  fails its signature), garbled or truncated, failing its signature (under the current
  key version or claiming another one), claiming rows past the chain head or a certified
  head row that is missing or rewritten (a signed retention purge excepted), or saved
  before a verification failure or discontinuity the chain records (an empty-chain row,
  audit head 0, included: every row this binary saves is `placed`; a row that carries a
  failure of its own included: above its audit head only the failure event naming the
  generation that recorded the row's failure is tolerated, any other, older, newer or
  without a generation, is a break the row never saw), or carrying no audit
  head at all (signed or re-signed by an older binary) while the chain holds the marker or
  a discontinuity event (except an older replica's re-sign recognised by
  INV-CORE-audit-verify-state-older-replica-resave-restarts), becomes a sticky
  `auditVerifyDiscontinuity`: status `broken` on every view (incremental, posture, full
  job) with the reason `audit verification state discontinuity (<kind>)`,
  `keyorix_audit_verify_failure_recorded` and `keyorix_audit_verify_state_discontinuity`
  at 1, a SECURITY log line and one `system.audit_verification_state_discontinuity`
  event. Every later save keeps it; no verification clears it. Only `admin audit
  accept-loss` moves a discontinuity of kind deleted, past the chain head or before a
  recorded break into the state's accepted list, together with a proven loss of rows
  (INV-CORE-audit-seal-never-valid-tamper-broken). Every save keeps a live marker
  in the chain. An honest first start (no row, no marker, no unauthenticated checkpoint
  artifact) is not a discontinuity. Not covered: a chain cut back past the marker with
  every checkpoint, high-water and state row deleted (indistinguishable in the database
  from a deployment that never checkpointed), and deployments without incremental
  verification (no state row); an older-binary row put back while retention has purged
  every marker and discontinuity event is only rejected (not_proven), as before. A
  mixed-version rolling upgrade where an older replica saves the state is restarted, not
  latched, under the conditions of INV-CORE-audit-verify-state-older-replica-resave-restarts
  (#3708). A save's generation stays above every generation a failure event names, so a
  lost row cannot make generations restart and collide. A failure event is appended
  only after the save that records its generation succeeds (a failed save appends
  none, and the next tick records the still-broken chain), so a transient save error
  is not a discontinuity; this holds for every caller that records a failure (the
  checkpoint tick, the rolling and job updates, and the key-transition prepare and
  completion). Fail-closed false positive: a
  failure event is appended after the lock is released, so if a full verification that
  started after the recording save clears that failure (or records another) before the
  append lands, the saved row reads as a discontinuity. Why: AUDIT-VERIFY-STATE-1, the residual risk of #3547.
  Guard: `TestAuditVerifyStateFailClosed_*` (`internal/core`, SQLite and PostgreSQL:
  `_RowDeleted`, `_RowDeletedWithLaunder`, `_RowDeletedMidRun`, `_RowGarbled`,
  `_RowFromOtherKeyEpoch`, `_RowPastChainHead`, `_RowBeforeKnownBreak`,
  `_LegacyRowBeforeKnownBreak`, `_OlderReplicaDropsDiscontinuity`,
  `_EmptyChainRowBeforeKnownBreak`, `_HonestFirstStart`,
  `_HonestUpgradeFromLegacyRow`, `_OlderFailureRowBeforeNewerFailure`,
  `_OlderFailureRowSavedAfterItsEvent`, `_RecordingRowAfterRestart`,
  `_ClearedFailureAtEventHead`, `_GenerationsOutliveLostRow`,
  `_UnplacedRowDiscontinuityEventOnly`, `_SaveFailureDuringBreak`), `TestAuditVerifyEvidence_ForeignFailure`,
  `TestAuditFailureEventGen`, `TestAuditKeyTransition_PrepareSaveFailureDuringBreak`.
