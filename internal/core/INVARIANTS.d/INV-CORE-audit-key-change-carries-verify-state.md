- **INV-CORE-audit-key-change-carries-verify-state** A change of the audit checkpoint key
  (`encryption rotate-kek`, `migrate-provider`) carries the signed verification state
  over under both keys; it never restarts it and never re-notarises a broken chain.
  `PrepareAuditKeyTransition` runs under the old key BEFORE any key file is written: it
  verifies the chain, saves the state (a failed walk becomes a sticky failure) and appends
  an `audit_key_transitions` record (both key versions, the certified head, the digests of
  the stored state, high-water mark, retention anchor and latest checkpoint, `seq`/`prev`)
  MACed by the old key and, over that MAC, by the new one.
  `CompleteAuditKeyTransition` runs with the new key, in the command after the commit and
  at every server start. It re-signs the anchor and the high-water mark, appends one
  `system.audit_key_transition` event and writes a fresh checkpoint (only when the chain
  verified). Last, it saves the state with `key_epoch`. Every step is idempotent. A state
  row is accepted under the new key only through an active record whose new-key MAC
  verifies and that names its exact digest. A record that is missing (while the state or
  an in-chain event names one), malformed, forged, for another key epoch, or whose
  certified head is gone (a signed purge excepted) is a sticky `key transition`
  discontinuity. Not covered: the online server cannot check the old-key MAC (it holds
  only the new key); offline verify-audit does that with `--previous-checkpoint-key-file`
  (`INV-AUDITVERIFY-key-transition-records-checked`). Why: AUDIT-ROTATE-TRANSITION-1,
  #3642, `docs/design-audit-key-transition.md`. Guard: `TestAuditKeyTransition_*`
  (`internal/core`, SQLite and PostgreSQL: `_RotationCarriesStateOver`,
  `_PurgedInstallStaysValid`, `_CarriesFailureOver`, `_CarriesDiscontinuityOver`,
  `_RecordMissing`, `_RecordForged`, `_RecordForWrongEpoch`,
  `_ForgedPendingRecordNotCompleted`, `_StateChangedAfterPrepareFailsClosed`,
  `_KillAfterPrepare`, `_KillAfterKeyCommit`, `_KillInsideComplete`, `_CompleteIdempotent`,
  `_TwoRotations`) and `TestRotateKEK_CarriesAuditStateOver`,
  `TestMigrateProvider_CarriesAuditStateOver` (`internal/encryptionops`, the real
  commands).
