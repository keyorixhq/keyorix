- **INV-ENCRYPTION-derived-keys-not-persisted-across-crash** The DEK and the three KEK/DEK-derived
  keys held only in application memory (the evidence-signing key, the audit-checkpoint key and the
  backup-manifest key — see `keymanager_io.go` and `service.go`) are never written to disk in
  cleartext, and a crash partway through a DEK or KEK rotation (passphrase change) followed by
  `RecoverInterruptedRotation` + `Initialize` must not spill them: no file under the key directory
  or inside a backup archive taken of the recovered install may contain any of those values
  byte-for-byte, neither the retired (pre-rotation) nor the freshly-minted (post-recovery) copy.
  Only the WRAPPED `dek.key` and the non-secret `kek.salt` live on disk. Why: a derived key left in
  cleartext on disk after a crash defeats the point of wrapping the DEK and signing with memory-only
  keys (the backup manifest and audit checkpoint become forgeable from disk access alone). Guard:
  `resguard_keylifecycle_pg_test.go:TestKeyLifecycleKeyLeakBackends` (SQLite + pg-gated PostgreSQL;
  crashes `RotateDEKWithSweep` at every durability checkpoint, recovers, scans the key dir for the
  raw DEK + all three derived keys; red-proofed by `:TestKeyLifecycleKeyLeakRedProof`) and the
  real-SIGKILL `resguard_keylifecycle_crash_test.go:FuzzKeyLifecycleCrashKeyLeak` (forks a killed
  rotation child, recovers, takes a backup, scans the tree AND the archive for the three derived
  keys only, pre- and post-recovery; it does NOT needle the raw DEK, which only the
  `TestKeyLifecycleKeyLeakBackends` guard above does). The fuzz target's tree scan and meter are
  red/green-proven by `:TestResguardKeyLeakRedGreen`; its archive scan, including the rule that an
  archive that is missing, not gzip, truncated or empty after a successful backup is itself a
  violation, is red/green-proven by `:TestResguardKeyLeakArchiveRedGreen` on hand-built archives.
  **Not covered**: a key leaked to a channel that is not a file
  under the scanned tree (process memory, swap, a log shipped off-box, a socket); secret *plaintext*
  spill (that is `FuzzFaultInjectedOperations`' canary scan); and a WRAPPED copy left where it should
  not be (only raw unwrapped bytes are needled, since the wrapped `dek.key` legitimately exists).
<!-- section: Crash consistency (write-pending → rename → fsync) -->
