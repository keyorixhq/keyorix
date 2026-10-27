- **INV-ENCRYPTION-sweep-verified-before-commit** A DEK-sweep rotation (`RotateDEKWithSweep`)
  commits only if every rewritten DEK-encrypted value decrypts under the NEW DEK: inside the
  sweep transaction, before the redo marker, the epoch compare-and-set and the COMMIT, a sample
  of the newest secret versions is round-tripped old DEK -> new DEK -> plaintext before the
  sweep writes (`rewrapCanary`), and after the sweep every row of every swept table is read
  back in id-ordered batches and opened with the new DEK and the row's AAD
  (`verifySweptRows`); the number opened must equal the number the sweep rewrote. Any failure
  rolls the transaction back, removes `dek.key.pending`, lifts the epoch fence and leaves the
  old DEK active; the error wraps `ErrSweepVerification` and names the table and row id, never
  a value. Why: one undecryptable version is data loss once the old DEK is retired
  (DEK-ROTATE-SAFETY-1). Guard: `sweep_verify_test.go:TestRotateDEKWithSweep_PreCommitVerify_UndecryptableRewrapCommitsNothing`
  (a GORM update callback damages one rewritten ciphertext per table and fault shape; nothing
  committed, the old DEK from disk decrypts every row), `sweep_verify_unit_test.go`
  (`_ErrorIsTyped`, `_CleanRotationPasses`, `TestRewrapCanary_RefusesBrokenNewDEK`),
  `sweep_verify_postgres_test.go` (pg-gated: the epoch stays on the old DEK). **Not covered**:
  a rewrite that encrypts the wrong plaintext under the new DEK decrypts and passes the full
  pass (only the canary sample compares plaintexts).
<!-- section: Crash consistency (write-pending → rename → fsync) -->
