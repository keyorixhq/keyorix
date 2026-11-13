- **INV-BACKUPFMT-oldrelease-restore-lossless** A v2 logical backup archive written by a
  real released binary in the N-2…N window (the fixtures carry what that tag's own
  `admin backup` emitted) must restore into current `main` losslessly: every secret version
  decrypts — under the restored keys and the exact `SecretAAD(secretID, projectID, version)`
  the old binary sealed it with — to its original plaintext; the restored audit chain
  verifies VALID; and roles, user→role grants and the user/token/machine-identity/project
  counts equal what the old code recorded. A second backup taken by current `main` of the
  restored data must round-trip again. This is the forward-compatibility promise the schema-
  epoch gate (`storage.SchemaEpochTooNew`, ADR-097) and the removed/legacy-column handling
  (`legacy_columns.go`) exist to keep; it is proven against what old binaries *actually
  wrote*, not against archives synthesised from current models. Why: task I6; differential
  oracle recorded by the OLD code (`scripts/i6-gen`, `expected.json`). Guard:
  `TestI6RestoreOldVersion` (`server/admin/i6_restore_oldversion_test.go`, SQLite and, when
  `KEYORIX_TEST_PG_DSN` is set, PostgreSQL).
  **Not covered**: a non-empty audit chain, pending key-rotation state and passphrase-change
  history are absent from the generated fixture (an empty chain verifies VALID); non-empty-
  chain old-release restore is covered by `TestAdminRestore_V0953Archive` and
  `TestBackupRestore_PropertyRoundTrip_V1ArchiveOnHEAD`, which use real binaries that wrote
  audit events.
