### Security
- **SQLite now refuses to boot under a wrong-key DEK, matching PostgreSQL.** A populated SQLite
  database records which DEK it is encrypted under (the `dek.epoch` fingerprint), and the server
  verifies it at start-up: starting with a DEK that is not the database's DEK is refused with a DEK
  epoch mismatch, instead of silently booting and writing rows under a second DEK. An existing
  database with no epoch row self-seeds on first boot after upgrade, only after the DEK decrypts the
  newest secret version — no `dek.key` format change, old key files load unchanged. A SQLite DEK
  rotation keeps the epoch consistent in the same transaction as the re-encryption sweep. Single
  node, so no runtime write-fence is involved (that stays PostgreSQL-only). Closes the
  PostgreSQL/SQLite asymmetry from fuzz-corpus#195 / KEYCOMMIT-2 item 4. Guard:
  `internal/encryption` `TestKeyCommitment_EpochGuard_SQLite`
  (INV-ENCRYPTION-sqlite-dek-epoch-at-boot).
