- **INV-ENCRYPTION-killed-write-state-wholly-before-or-after** After a kill, secrets, roles
  and authorization decisions are together the state before the operation or together the state
  after it, never some from each. A DEK rotation's stored versions are all rewritten or none,
  and exactly one passphrase opens the install after a killed KEK rotation. Why: the sweep's
  rows and the redo marker share one transaction, and the role changes commit with their audit
  rows; a split transaction would leave a mix. Guard:
  `process_crash_recovery_fuzz_test.go:FuzzProcessCrashRecovery`, `:TestProcessCrashExhaustive`
  (on request), `process_crash_recovery_redproof_test.go:TestProcessCrashRedProof`. **Not
  covered**: SQLite only; the "exactly one passphrase" branch is proven only by offering the
  same passphrase twice, because a real two-passphrase state cannot be constructed; state the
  model does not read (audit chain, tags, notification rows).
<!-- section: Crash consistency (write-pending → rename → fsync) -->
