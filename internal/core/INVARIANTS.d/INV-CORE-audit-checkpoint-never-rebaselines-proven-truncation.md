- **INV-CORE-audit-checkpoint-never-rebaselines-proven-truncation** No checkpoint write
  (`writeAuditCheckpointLocked`, the full walk; `writeIncrementalCheckpointLocked`, the
  tail check) certifies a chain that the signed audit verification state proves was
  truncated while that state is still authentic under the current key. That state pins
  the newest certified count and head row (`auditVerifyPin`, never lowered by a save).
  The `key_version` of a checkpoint or high-water mark that fails its HMAC is not
  authenticated. It is never accepted as proof of a key change when an authentic artifact
  under the current key contradicts it. A genuine key change (rotate-kek writes nothing to
  the database) invalidates the state too, so re-baselining after one still works. An
  actor who also garbles or deletes the state row no longer gets a silent re-baseline: the
  write still proceeds, but under a sticky discontinuity
  (INV-CORE-audit-verify-state-never-silently-restarts). Not covered: a deployment that
  never ran the checkpoint scheduler (no state row). Why: RECOVERY-DESIGN-1 F1. Guard:
  `TestAuditCheckpointLaunder_FullPathRefuses`, `_IncrementalPathRefuses` (both also
  `_Postgres`, pg-gated), `_RefusedAfterCountRecovers`,
  `_TailPathRefusesAfterNewerCheckpointsDeleted`, `_PinSurvivesUntrustedSave`, and
  `_KeyRotationStillRebaselines` for the other direction.
