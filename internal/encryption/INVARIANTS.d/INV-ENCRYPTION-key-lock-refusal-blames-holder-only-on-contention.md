- **INV-ENCRYPTION-key-lock-refusal-blames-holder-only-on-contention** A refused
  `AcquireExclusiveKeyLock`/`AcquireSharedKeyLock` tells the operator that a server or
  another process holds the key directory only when flock reported contention
  (EWOULDBLOCK). A missing key directory (`KeyDirMissingError`), permission denied and
  any other open failure are returned with their own cause, because "stop the running
  server" sends the operator the wrong way when no server is running. Callers add the
  hint through `WithLockContentionHint`. Why: #3742, MSG-ACCURACY-1, REVIEW-3933-DEEP-1
  F2. Guard: `internal/encryption/key_lock_hint_callers_guard_test.go`
  (`TestKeyLockRefusalsBlameAHolderOnlyOnContention` over every production caller,
  `TestKeyLockCallerFindings_Calibration`), plus the per-caller behaviour tests
  `TestOpenKeyWriter_LockRefusalMessageMatchesTheCause` (internal/encryptionops) and
  `TestAdminKeyLockRefusal_MessageMatchesTheCause` (server/admin). **Not covered**:
  blame wording built outside a string literal in the refusal branch (a constant, or a
  helper that formats its own message); the guard matches phrases, not meaning.
