- **INV-ENCRYPTION-killed-write-rerun-completes-or-refuses** Rerunning an interrupted
  operation on the recovered install ends cleanly or refuses with an explanation, and leaves an
  allowed state: no panic, no silent corruption, and a fresh-install migration converges on the
  schema a clean migration produces. Why: the documented answer to an interrupted operation is
  to run it again. Guard: `process_crash_recovery_fuzz_test.go:FuzzProcessCrashRecovery`,
  `:TestProcessCrashExhaustive` (on request),
  `process_crash_recovery_redproof_test.go:TestProcessCrashRedProof`. **Not covered**: the SQLite leg only (the PostgreSQL leg, process_crash_recovery_pg_fuzz_test.go, states its own coverage); a second kill during the rerun; migration of an older schema (fresh install only).
<!-- section: Crash consistency (write-pending → rename → fsync) -->
