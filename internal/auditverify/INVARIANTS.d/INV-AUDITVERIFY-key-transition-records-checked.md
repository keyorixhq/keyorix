- **INV-AUDITVERIFY-key-transition-records-checked** With a checkpoint key that
  authenticates the latest checkpoint, `Verify` checks the `audit_key_transitions` records
  (a byte-identical reimplementation of `internal/core`'s format; `ParseKeyTransitions`
  checks `seq`, `prev` digests and key-version linkage). The record for the current epoch
  must verify its new-key MAC under the supplied key and its certified head must still be
  in the chain (an authenticated purge excepted). A pending record (old key version =
  current) must verify its old-key MAC. Any other last record is another epoch. Every
  in-chain `system.audit_key_transition` event must name a held record, and an event
  without the row is a missing record. Each of these failures is BROKEN. A previous key
  (`PreviousCheckpointKeys`, `--previous-checkpoint-key-file`) that signs the checkpoint a
  record names, under the record's old key version, must also verify that record's
  old-key MAC (BROKEN otherwise). A record whose old-key MAC was not checked is listed in
  `NotProven`. A rotation by an older binary (no row, no event) is unchanged. Why:
  AUDIT-ROTATE-TRANSITION-1, #3642, `docs/design-audit-key-transition.md`. Guard:
  `TestKeyTransition_*` (`keytransition_differential_test.go`: `_NormalRotationValidOffline`,
  `_FormatMatchesCore`, `_RecordMissingBrokenOffline`, `_RecordForgedBrokenOffline`,
  `_ForgedByNewKeyHolderBrokenWithPreviousKey`, `_OldKeyMACForgedBrokenWithPreviousKey`,
  `_RecordForWrongEpochBrokenOffline`, `_LegacyRotationWithoutRecordUnchanged`).
