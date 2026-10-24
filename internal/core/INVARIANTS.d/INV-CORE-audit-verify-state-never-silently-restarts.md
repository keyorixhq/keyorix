- **INV-CORE-audit-verify-state-never-silently-restarts** Audit verification never
  starts over from whatever state row it finds. A row that is deleted (while the chain
  holds a `system.audit_verification_state_initialized` marker or a discontinuity event,
  while this process already read one, or while the latest checkpoint or high-water mark
  fails its signature), garbled or truncated, failing its signature (under the current
  key version or claiming another one), claiming rows past the chain head or a certified
  head row that is missing or rewritten (a signed retention purge excepted), or saved
  before a verification failure or discontinuity the chain records (an empty-chain row,
  audit head 0, included: every row this binary saves is `placed`), or carrying no audit
  head at all (signed or re-signed by an older binary) while the chain holds the marker or
  a discontinuity event, becomes a sticky
  `auditVerifyDiscontinuity`: status `broken` on every view (incremental, posture, full
  job) with the reason `audit verification state discontinuity (<kind>)`,
  `keyorix_audit_verify_failure_recorded` and `keyorix_audit_verify_state_discontinuity`
  at 1, a SECURITY log line and one `system.audit_verification_state_discontinuity`
  event. Every later save keeps it; no verification clears it (an audited acceptance is a
  design proposal, `docs/design-audit-reseal-options.md`). Every save keeps a live marker
  in the chain. An honest first start (no row, no marker, no unauthenticated checkpoint
  artifact) is not a discontinuity. Not covered: a chain cut back past the marker with
  every checkpoint, high-water and state row deleted (indistinguishable in the database
  from a deployment that never checkpointed), and deployments without incremental
  verification (no state row); an older-binary row put back while retention has purged
  every marker and discontinuity event is only rejected (not_proven), as before. A
  mixed-version rolling upgrade where an older replica saves the state reads as this
  discontinuity: stop older replicas before upgrading. Why: AUDIT-VERIFY-STATE-1, the residual risk of #3547.
  Guard: `TestAuditVerifyStateFailClosed_*` (`internal/core`, SQLite and PostgreSQL:
  `_RowDeleted`, `_RowDeletedWithLaunder`, `_RowDeletedMidRun`, `_RowGarbled`,
  `_RowFromOtherKeyEpoch`, `_RowPastChainHead`, `_RowBeforeKnownBreak`,
  `_LegacyRowBeforeKnownBreak`, `_OlderReplicaDropsDiscontinuity`,
  `_EmptyChainRowBeforeKnownBreak`, `_HonestFirstStart`,
  `_HonestUpgradeFromLegacyRow`).
