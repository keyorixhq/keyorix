- **INV-CORE-audit-writer-recovers-own-build** A function that builds a `models.AuditEvent`
  in its own frame and then emits it recovers a panic in that frame itself
  (`defer besteffort.RunRecover("audit.<name>")()`, which logs and counts it in
  `keyorix_best_effort_failures_total`, or a `defer func(){ recover() }()`).
  `emitAudit`/`emitAuditOn` recover only once control reaches them, so a panic while the
  event is built (`actorTypeFromContext`, `impersonatorFromContext`, `sanitizeAuditText`)
  would otherwise escape to a caller whose answer is already decided: a deny path's denial,
  or a post-commit best-effort step. `writeAuditEventDiffOn` (#2561), `writeAuditEventFailed`
  (INVARIANT-GUARDS-1 observation 4: ~22 deny-path audits and the `session_undelivered.go`
  steps), `writeSecretReadDenialRow`, `auditBusinessHoursConfig`, `SetRetentionPolicy`,
  `AuditLicenseState` and the two security-posture writers do. The exception is an
  audit-before-disclosure writer that returns an error (`LogSecretReadWithProject`,
  `logSecretMetadataAccess`): a recover there would return nil and the caller would
  disclose with no audit row, so a propagating panic is the fail-closed outcome. Why:
  `writeAuditEventFailed` had no recover while its siblings did.
  Guard: `internal/core/guards/audit_writer_recover_guard_test.go`
  `TestAuditEventWritersRecoverTheirOwnPanic` (every core family function containing a
  `models.AuditEvent` literal must recover, or be named in `auditWriterRecoverExempt` with a
  reason; stale entries fail) and `audit_failed_panic_recover_test.go`
  `TestWriteAuditEventFailed_PanicLeavesTheDenyAnswerUnchanged` (a panicking storage stub and
  a panic during event construction: the deny answer is unchanged, the construction panic
  is counted once).
  **Not covered**: the two `impersonation.go` writers are listed OPEN until FIX-3277 lands;
  a builder inside a function literal, outside the core family, or built without a
  composite literal is not seen.
