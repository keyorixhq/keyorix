- **INV-CORE-recovery-code-reauth-consumed-with-the-change** An unused recovery code
  re-authenticates exactly two factor changes, `DisableMFA` and `RegenerateMFARecoveryCodes`
  (`reauthWithRecoveryCode`); `requireReauth` itself and its other callers do not take one. The
  code is checked with the login path's own conditional consume (`consumeRecoveryCodeRecovering`)
  inside ONE transaction with the change, after `LockUserForUpdate` under the account's
  `loginFailureMu` shard: a consume or change failure rolls both back (the code stays unused). A
  locked account (caller's snapshot, or the row under the lock) is refused before the code is
  consumed. Every refusal after the match (the change's error or panic, the commit) answers the
  wrong-code `reauthRejectedError` text, is counted by `recordFailedLogin` and audited `mfa.error`;
  a wrong or used code is counted once (by `requireReauth`, which it falls through to); a fault on
  the row lock or the consume reaches no verdict and is not counted. Two concurrent requests with
  one code: at most one succeeds. FIPS 140-only mode does not change the path (SHA-256 codes).
  Only the request's `code` reaches `reauthWithRecoveryCode`; the `password` is a separate
  argument of both core methods and goes to `requireReauth` alone, so a password is never
  SHA-256'd or consumed as a recovery code (`go/weak-sensitive-data-hashing`).
  Why: #4224; a rolled-back code is still valid, so any other answer would confirm it.
  Guard: `internal/core/mfa_recovery_reauth_test.go` (`TestRecoveryReauth_*`,
  `TestDisableMFA_RecoveryCode_*`, `TestRegenerateRecoveryCodes_RecoveryCode_*`; the password
  split: `TestRecoveryReauth_RecoveryCodeSentAsPasswordIsNeverConsumed`,
  `TestRecoveryReauth_PasswordEqualToAnUnusedRecoveryCodeTakesThePasswordPath`, and at the
  handler `server/http/handlers/mfa_recovery_password_field_test.go`),
  `internal/core/mfa_recovery_reauth_internal_test.go:TestReauthWithRecoveryCode_LockedUnderTheRowLock`,
  `internal/core/mfa_recovery_reauth_postgres_test.go:TestRecoveryReauth_ConcurrentSameCode_CrossReplicaPostgres` (pg-gated).
