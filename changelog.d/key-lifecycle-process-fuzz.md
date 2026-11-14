### Testing
- **Process-level key-lifecycle fuzzer (`FuzzKeyLifecycleProcess`, `server/admin`).**
  Drives the full key lifecycle — create/update/delete secret, DEK rotation (+sweep),
  KEK/passphrase rotation, backup, restore into a fresh store, SIGKILL of a rotation
  child, concurrent writers, SIGKILL of a lock holder, documented recovery
  (`encryption upgrade-aad`), reopen — as REAL child processes, so the cross-process
  `dek.lock` flock the in-process backup fuzzer could not drive (#4104/#4105) is
  exercised directly. Oracles (each with a watched red/green proof, `TestKLRedProof_*`):
  the store always opens or returns a documented typed error (never a panic); every
  acknowledged write decrypts to its exact plaintext; a restore of a pending-rotation
  backup starts or fails with a documented error, never undecryptable secrets; after the
  documented recovery command the store is usable with no hand repair; two concurrent
  rotations never both proceed and a killed holder never blocks the lock forever. Ships a
  deterministic replay matrix (`TestKeyLifecycleProcessReplay`, both backends) and a
  Postgres corpus-replay test (`TestKeyLifecycleProcessCorpusPostgres`). SQLite always;
  Postgres via `KEYORIX_TEST_PG_DSN` (isolated `v3_*` databases, dropped on cleanup).
  ~108 min of real fuzzing across 12 chunks found no oracle violation; guards two new
  invariants (`INV-ADMIN-keylifecycle-rotation-lock-mutual-exclusion`,
  `INV-ADMIN-keylifecycle-interrupted-rotation-auto-recovers`).
