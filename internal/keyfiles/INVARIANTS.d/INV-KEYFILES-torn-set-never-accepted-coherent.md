- **INV-KEYFILES-torn-set-never-accepted-coherent** Boot never accepts a key set that is not
  one coherent generation: `VerifyKeySetConsistency`/`ReconcileKeySet` return a non-nil error
  for a FOREIGN file (content matching neither its recorded nor a staged manifest hash), a
  PARTIAL set (some required files present, some missing), or a STUCK interrupted intent (some
  files new, some old, no staging file holding the content the operation was about to write);
  and after a SUCCESSFUL reconcile every present required file hashes to its committed manifest
  entry — the set is provably one generation. A refused reconcile leaves the old active files
  byte-for-byte unchanged (no half-rename); a finishable one moves the whole set to the staged
  generation (old-or-new, never a mix). An unparseable manifest is moved aside and the present
  set re-adopted (warn-and-adopt), never a crash. Why: `consistency.go` `InspectKeySet` doc
  comment; `manifest.go` package comment; ADR-112 / #2900. This is the reader/crash-reconcile
  counterpart to the WRITE-seam fault fuzzing in `internal/encryption`
  (`FuzzFaultInjectedOperations`). Guard: `FuzzKeySetCrashReconcile`
  (crash_reconcile_fuzz_test.go).
