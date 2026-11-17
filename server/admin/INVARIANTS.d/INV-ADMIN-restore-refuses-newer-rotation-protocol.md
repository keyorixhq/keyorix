- **INV-ADMIN-restore-refuses-newer-rotation-protocol** `admin restore` (v1 and v2, SQLite and
  PostgreSQL, with or without `--overwrite-existing`/`--replace-existing-data`/`--allow-rollback`)
  refuses a target whose database records a DEK rotation protocol
  (`system_metadata["dek.rotation_protocol"]`, written by every server start) newer than this
  binary's, or one that does not parse (`encryption.ErrRotationProtocolTooOld`). The refusal
  comes with the other target checks, before the archive is extracted and before any key file
  or manifest is staged, so the key files, the key-set manifest and the database are
  byte-identical afterwards. A target without a database, `system_metadata` or the marker
  passes. Why: an older admin binary replacing a newer deployment's key files and rows is the
  same hazard as it rotating them (INV-ENCRYPTION-rotation-protocol-never-older;
  KEY-ROTATION-TAILS-NOV-1 item 3). Guard: `server/admin/restore_rotation_protocol_refusal_test.go`
  (the Postgres case pg-gated), `server/sqlite_rotation_protocol_integration_test.go`. Not
  covered: binaries that predate the marker never read it.
<!-- section: Backup and restore -->
