- **INV-CORE-mfa-replay-consume-fail-counts-lockout** `VerifyMFACredentials`
  (`mfa.go`) must call `recordFailedLogin` BOTH when the TOTP code matched but
  the anti-replay write failed (the `codeMatched && storageErr != nil` branch)
  AND when the code did not match (the normal wrong-code path). Without the
  failed-login record on the matched-but-replay-write-failed path, an attacker
  who submits a correct TOTP code that happens to race a replay-storage error
  gets no lockout increment — a timing-discernible difference from the
  wrong-code path would let them confirm the code was correct. The two
  `recordFailedLogin` calls differ in whether the lockout message mentions a
  storage error; both count toward the login lockout counter, ensuring the
  response-time profile does not distinguish "code correct, storage failed"
  from "code wrong". What this invariant does NOT cover: the case where both
  paths are absent (the guard counts calls, not their semantics); and the
  question of whether `recordFailedLogin` itself prevents lockout bypass under
  Postgres replica races (covered separately by the cross-replica lockout
  tests).
  Guard: `internal/core/guards`
  `TestTimingEqualization_MFACodeMatchedStorageError_CountsTowardLockout`
  (counts exactly 2 `recordFailedLogin` calls in `VerifyMFACredentials`).
  Confirmed red when the matched-but-failed branch's `recordFailedLogin` call
  was removed and green when restored.
