- **INV-ENCRYPTION-sqlite-dek-epoch-at-boot** On SQLite, as on PostgreSQL, a populated database
  refuses to boot under a wrong-key DEK. `StartDEKEpochGuard` verifies the DEK epoch
  (`system_metadata["dek.epoch"]`, a fingerprint, `dek_epoch.go`) at boot on SQLite too: it
  returns a wrapped `ErrDEKEpochMismatch` when this server's DEK fingerprint is not the database's
  recorded epoch, seeds an absent epoch only after this DEK decrypts the newest encrypted secret
  version (`probeDecryptsNewestSecretVersion` — so an old `dek.key` loads unchanged, no file-format
  change, and self-seeds), and a fresh database seeds cleanly. SQLite is single node, so there is
  **no watcher goroutine and no write fence** (unlike the PostgreSQL path, see
  [[INV-ENCRYPTION-dek-epoch-cross-replica]]) — the check is boot-time only, and the handle is not
  kept. A SQLite DEK rotation keeps the epoch consistent by setting it to the new DEK's fingerprint
  in the sweep's own transaction (`setDEKEpochOnSQLiteRotation`), atomically with the re-encryption
  and never through a `rotating:<old>` fenced state. A restore is untouched: it installs the
  archive's database image (carrying its own epoch row) and the archive's key files together as one
  consistent set, so the restored epoch always names the restored DEK. Why: fuzz-corpus#195 /
  KEYCOMMIT-2 item 4 (`wrapKey` is not key-committing, so one `dek.key` can open under two KEKs to
  two DEKs — on SQLite a populated database could boot under the second DEK, splitting rows across
  two DEKs). Guard: `key_commitment_epoch_db_test.go:TestKeyCommitment_EpochGuard_SQLite` (never
  SKIPs — SQLite is the default backend), `dek_epoch_test.go:TestDEKEpoch_SQLiteBootSeedsAndRotationKeepsEpoch`,
  `rotation_protocol_sqlite_start_test.go:TestStartDEKEpochGuard_SQLiteRecordsRotationProtocol`.
  **Not covered**: the PostgreSQL watcher/fence runtime path ([[INV-ENCRYPTION-dek-epoch-cross-replica]],
  pg-gated tests); concurrent boots of one SQLite file (single node by construction — one process
  holds the database and `dek.lock`); a corrupted/garbage epoch row (treated as a plain mismatch,
  which refuses the boot — fail closed); the value-AEAD key commitment (this binds the DEK to the
  database, not a colliding secret-value ciphertext). See also [[INV-ENCRYPTION-rotation-protocol-never-older]].
<!-- section: First-boot / cross-process coordination -->
