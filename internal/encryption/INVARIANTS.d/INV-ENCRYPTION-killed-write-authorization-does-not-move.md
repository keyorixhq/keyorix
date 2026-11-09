- **INV-ENCRYPTION-killed-write-authorization-does-not-move** After a kill, every
  authorization probe (each fixture user, each of four permissions, at global, project and
  environment scope) gives the decision it gave before the operation or the one a clean run of
  the operation produces. A killed role change never widens or narrows access to any third
  value. Why: a partly applied grant or revoke fails silently in the direction of the crash.
  Guard: `process_crash_recovery_fuzz_test.go:FuzzProcessCrashRecovery`,
  `:TestProcessCrashExhaustive` (on request),
  `process_crash_recovery_redproof_test.go:TestProcessCrashRedProof`. **Not covered**: SQLite
  only; subjects and permissions outside the fixed probe set; group grants and shares.
<!-- section: Crash consistency (write-pending → rename → fsync) -->
