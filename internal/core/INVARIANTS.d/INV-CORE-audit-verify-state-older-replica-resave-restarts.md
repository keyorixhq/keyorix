- **INV-CORE-audit-verify-state-older-replica-resave-restarts** An authentic state row
  without a placement (`Placed`/`audit_head`), loaded while the chain holds a
  `system.audit_verification_state_initialized` marker, is an older replica's re-sign during a
  mixed-version rolling upgrade or after a rollback (#3708), and is restarted (`not_proven`,
  the row's failure kept, a `system.audit_verification_state_rejected` event, re-placed by the
  next passing full verification that starts after it) instead of latching a sticky
  discontinuity, only when every one of these holds: no discontinuity event exists; the newest
  marker names the state generation of the save that placed the state (`auditVerifyMarkerText`;
  every save appends one when the newest marker names none) and the row's generation is
  higher (every row from before the upgrade has a lower one); no failure event names a higher
  generation, and, when the row carries no failure, no failure event without a generation lies
  above the marker; and the row is not older than the signed checkpoint trail or than a
  generation this process read. Otherwise it is the `before a recorded break` discontinuity of
  INV-CORE-audit-verify-state-never-silently-restarts. So an older replica's save no longer
  makes `audit verify`, the posture and `keyorix_audit_verify_failure_recorded` read broken with
  no clearing command, while a row from before the upgrade, a replayed one, one saved before a
  recorded break and a re-sign that dropped a discontinuity still latch, and a deleted or
  rewritten chain row still reads broken. Why: #3708 (Helm `RollingUpdate`, ADR-039). Guard:
  `internal/core/audit_verify_state_rolling_upgrade_test.go` (`TestAuditVerifyStateRollingUpgrade_OlderReplicaResaveHeals`,
  `_RealDeletionStillBroken`, `_ResaveBeforeRecordedBreakLatches`, `_StaleResaveLatches`) and
  `audit_verify_state_rolling_upgrade_marker_test.go` (`_PreUpgradeRowLatches`,
  `_UnnamedMarkerLatches`, `_UnnamedMarkerIsRenamed`, `_UnnamedFailureAboveMarkerLatches`,
  `TestAuditVerifyMarkerGen`), SQLite and PostgreSQL. Not covered: a deployment whose newest
  marker predates #3708 latches an older replica's re-sign saved before its first save under
  this version (the marker is renamed by that save); the in-process generation condition has no
  test of its own; an older replica's re-sign while an accepted loss or a key transition exists
  is still a discontinuity (it drops `seals`/`key_epoch`; the seal and key-transition checks run
  first).
