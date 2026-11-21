- **INV-ENCRYPTION-killed-write-secrets-read-back** Every secret version that existed before
  a killed operation still decrypts to its value once the install reopens, unless the operation
  completed and legitimately replaced it (restore, update). Why: a half-applied DEK sweep or key
  rename loses secrets without any error at the moment of the crash. Guard:
  `process_crash_recovery_fuzz_test.go:FuzzProcessCrashRecovery`, `:TestProcessCrashExhaustive`
  (on request), `process_crash_recovery_redproof_test.go:TestProcessCrashRedProof`. **Not
  covered**: the SQLite leg only (the PostgreSQL leg, process_crash_recovery_pg_fuzz_test.go, states its own coverage); operations outside the harness's `pcrashOps` list (provider migration,
  secret delete, shares, group grants); fsync and power loss.
<!-- section: Crash consistency (write-pending → rename → fsync) -->
