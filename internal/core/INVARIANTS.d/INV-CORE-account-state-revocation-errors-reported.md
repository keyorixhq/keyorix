- **INV-CORE-account-state-revocation-errors-reported** Inside `setAccountStateInTx` (suspend,
  deactivate, require-password-reset, OTP reissue, user-to-machine migration) no storage error of
  the credential sweep is discarded: the session listing, the PAT listing, the session delete and
  the PAT revocation each run in a savepoint with one retry, and a failure that persists is
  carried to the post-commit step (`sessionEvictions.ListErr` / `.RevokeErr`), which evicts every
  auth-cache entry of the user, logs a `SECURITY:` line and writes
  `EventSessionRevocationFailed`. The state change itself is never rolled back for it (a
  narrowing decision is never blocked). Why: ERRLOSS-REVOKE-1 (#3777) for the session listing;
  AUTHZ-ORACLE-1 for the PAT listing and the revocations, where a discarded error committed a
  suspension with the PATs still live in storage (usable again on reactivation) and nothing
  reported. Guard: `account_state_pat_failure_test.go` (one-off faults retried, SQLite and
  Postgres), `account_state_pat_failure_persistent_test.go` (persistent failures reported),
  `session_eviction_list_failure_test.go`.
  **Not covered**: the auth-cache entries themselves when no per-user evictor is wired (the log
  line says so), and session cleanup outside a transaction (`RefreshSession` deleting an
  already-refused session).
