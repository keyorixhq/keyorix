- **INV-ENCRYPTION-killed-write-install-opens-or-refuses** After a process running a real
  admin or core write is SIGKILLed at any write seam, the install reopens through the server
  boot steps, or refuses with an error the product documents a recovery for (the restore
  journal, an inconsistent key set, a passphrase that does not unwrap the DEK). It never panics
  and never fails for an unexplained reason. Why: the crash windows of key rotation and restore
  span the database and the key files. Guard:
  `process_crash_recovery_fuzz_test.go:FuzzProcessCrashRecovery`, `:TestProcessCrashExhaustive`
  (on request), `process_crash_recovery_redproof_test.go:TestProcessCrashRedProof`. **Not
  covered**: SQLite only; SIGKILL leaves the page cache to the kernel, so nothing here tests
  fsync or power loss; the harness copies the server boot order by hand, and a drift between
  the two is not detected.
<!-- section: Crash consistency (write-pending → rename → fsync) -->
