### Testing
- **Backup / restore / key-rotation modelled as one state machine (C2).** A new
  sequence fuzzer (`FuzzBackupRotationSequences`, SQLite in CI;
  `FuzzBackupRotationSequencesPG`, gated on `KEYORIX_TEST_PG_DSN`) drives random
  sequences over rotate-dek, rotate-kek, backup, restore-to-a-clean-host,
  kill-at-a-seam, start-the-server-once and read-all-secrets, checking two
  oracles that cannot false-positive: the backup contract (refuse with no
  archive, or produce an archive that restores on a clean host and decrypts) and
  ledger equality (same secret names/versions/values before and after). Planted
  defects with silent controls red-proof both oracles (a backup that drops a DEK
  `.pending`; a mixed-generation key set). Registered in
  `scripts/fuzzing/targets.conf`.
- **Reproduced the multi-replica backup gap (H1).**
  `TestAdminBackup_Postgres_StateB_OtherKeyDir_UndecryptableArchive` shows that
  under `storage.encryption.key_dir_lock: database`, a backup taken from a
  replica whose key directory holds the old DEK (no `.pending`) while the
  database rows and the redo marker are under the new DEK is NOT refused, and the
  archive it writes restores on a clean host but neither decrypts nor lets the
  server start (the DEK epoch guard refuses it). Characterizes the gap against
  live PostgreSQL; the fix is proposed in the C2 report, no production code
  changed here.
- **Demonstrated the stale-salt backup outage (H2).**
  `TestAdminBackup_StaleSaltPending_RefusesEveryBackupUntilDeleted` shows that a
  `kek.salt.pending` left by a rotate-kek that never changed the active keys
  survives a successful boot (reconcile only warns) and then makes every later
  `admin backup` refuse until the file is deleted by hand, with no audit event
  (the refusal runs before storage is opened).
