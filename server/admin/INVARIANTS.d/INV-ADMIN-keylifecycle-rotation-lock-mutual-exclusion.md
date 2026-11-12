- **INV-ADMIN-keylifecycle-rotation-lock-mutual-exclusion** Two key-writing processes
  (a DEK/KEK rotation, or a rotation against a live server) never both proceed: the
  exclusive `dek.lock` flock (`acquireExclusiveKeyLock`, `LOCK_EX|LOCK_NB`) refuses the
  second with `syscall.EWOULDBLOCK` ("another process already holds the DEK lock"), and a
  holder that is SIGKILLed never leaves a lock that blocks forever — flock releases on
  process exit, so a later rotation against the same key directory then succeeds. Why: a
  second writer promoting a new DEK while the first still holds the old one in memory is
  permanent data loss (ADR-010, #92/#196); the task-V3 process-level campaign confirmed
  the flock holds across real OS processes, which the in-process backup fuzzer could not
  drive (#4104). Guard: `server/admin/keylifecycle_process_fuzz_test.go`
  (`TestKLRedProof_OracleE_Lock` — watched red/green: free lock → rotation succeeds,
  held lock → refused with lock-held, killed holder → rotation succeeds again),
  `TestKeyLifecycleProcessReplay` (`concurrent_rotate_refused`, `killed_lockholder_unblocks`).
