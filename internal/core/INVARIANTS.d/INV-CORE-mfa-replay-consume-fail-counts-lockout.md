- **INV-CORE-mfa-replay-consume-fail-counts-lockout** `VerifyMFACredentials`
  (`mfa.go`) must call `recordFailedLogin` BOTH when the TOTP code matched but
  the anti-replay write failed (the `codeMatched && storageErr != nil` branch)
  AND when the code did not match (the normal wrong-code path). Without the
  failed-login record on the matched-but-replay-write-failed path, an attacker
  who submits a correct TOTP code that happens to race a replay-storage error
  gets no lockout increment — a timing-discernible difference from the
  wrong-code path would let them confirm the code was correct. The two calls
  are identical (`c.recordFailedLogin(ctx, user)`); only the errors the two
  branches return differ. Both count toward the login lockout counter, so the
  response-time profile does not distinguish "code correct, storage failed"
  from "code wrong". The step-up re-auth path `requireReauth` (`mfa.go`) has
  the same pair of branches (credential matched but a consumption write
  failed; credential wrong) and the same rule. What this invariant does NOT
  cover: the position of the calls (the guard counts calls, not which branch
  holds them); and whether `recordFailedLogin` itself prevents lockout bypass
  under Postgres replica races (covered separately by the cross-replica
  lockout tests).
  Guard: `internal/core/guards`
  `TestTimingEqualization_MFACodeMatchedStorageError_CountsTowardLockout`
  (exactly 2 `recordFailedLogin` calls in `VerifyMFACredentials`) and
  `TestTimingEqualization_RequireReauthPostVerdictFailureCountsTowardLockout`
  (exactly 2 in `requireReauth`). Confirmed red when the matched-but-failed
  branch's `recordFailedLogin` call was removed and green when restored.
