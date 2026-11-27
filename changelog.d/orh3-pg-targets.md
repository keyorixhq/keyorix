### Testing

- oracle-health planted-defect entries for the four DB-backed fuzz harnesses that had no entry:
  `kdf-enum-absent-compare` (FuzzKDFEnumerationOracle: absent-user dummy-KDF compare),
  `dek-sweep-recover-discard` (FuzzDEKSweepCrashConsistency: recovery availability oracle),
  `connect-ref-dot-segment` (FuzzConnectRefScopingGRPC: dot-segment traversal bypass),
  `fault-injected-sql-fail-closed` (FuzzFaultInjectedOperations: sql:create-version fail-closed oracle).
  All four: control PASS, planted DETECTED.
