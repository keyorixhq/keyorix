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
  above the marker; the row is not older than the signed checkpoint trail or than a
  generation this process read; and the row carries no rejection, whatever its generation,
  other than this binary's own restart of a re-sign (`auditVerifyResavedRE`): an older
  replica whose load rejected the row (deleted, put back below a generation it read, older
  than the trail, garbled) saves at the next generation and the current trail, so only that
  rejection, kept by its later saves, tells its laundering save from an honest re-sign
  (REVIEW-3854-DEEP-1). The rejection's generation does not: an older replica started before
  the upgrade read a generation below the marker's, stamps its rejection below it too, and its
  next save is above it (REVIEW-3854-DEEP-2). Otherwise it is the `before a recorded break` discontinuity of
  INV-CORE-audit-verify-state-never-silently-restarts. So an older replica's save no longer
  makes `audit verify`, the posture and `keyorix_audit_verify_failure_recorded` read broken with
  no clearing command, while a row from before the upgrade, a replayed one, one saved before a
  recorded break, a re-sign that dropped a discontinuity and an older replica's save after it
  rejected the row (a deletion or put-back it would otherwise launder) still latch, and a deleted or
  rewritten chain row still reads broken. Why: #3708 (Helm `RollingUpdate`, ADR-039). Guard:
  `internal/core/audit_verify_state_rolling_upgrade_test.go` (`TestAuditVerifyStateRollingUpgrade_OlderReplicaResaveHeals`,
  `_RealDeletionStillBroken`, `_ResaveBeforeRecordedBreakLatches`, `_StaleResaveLatches`) and
  `audit_verify_state_rolling_upgrade_marker_test.go` (`_PreUpgradeRowLatches`,
  `_UnnamedMarkerLatches`, `_UnnamedMarkerIsRenamed`, `_UnnamedFailureAboveMarkerLatches`,
  `TestAuditVerifyMarkerGen`) and `audit_verify_state_rolling_upgrade_rejecting_test.go`
  (`_OlderReplicaRejectingResaveLatches`: deleted, deleted then more saves, garbled, put back
  below the generation read, stale trail; `_OlderReplicaRejectionBelowMarkerLatches`: the
  rejection stamped below the marker's generation, one and three saves after the upgrade;
  `TestAuditVerifyResavedRE`), SQLite and PostgreSQL.
  Not covered: an older replica that rejected the row and then completed a full verification
  started after the rejection, before any replica of this version loaded the row, has cleared
  the rejection and its row passes as a re-sign; an older replica restarted after the row
  was deleted (it read no generation) loads it as empty and records no rejection, and its row
  passes as a re-sign once its saves climb above the marker's generation, every failure
  generation and the generation every replica of this version read with none of them saving
  in between (about as many saves as the marker's generation; one per interval, 24h by
  default); a rejection a row still carries (a replay this binary rejected, or one from before
  the marker that no full verification has cleared yet) latches (fail closed, a false latch
  like the replay one) once an older replica re-signs the row; the marker is appended after
  the save that placed the state, outside the checkpoint lock, so a failure event without a
  generation that an older replica appends in that gap lies below the marker and does not
  latch a row without a failure; a deployment whose newest
  marker predates #3708 latches an older replica's re-sign saved before its first save under
  this version (the marker is renamed by that save); the in-process generation condition has no
  test of its own; an older replica's re-sign while an accepted loss or a key transition exists
  is still a discontinuity (it drops `seals`/`key_epoch`; the seal and key-transition checks run
  first).
