- **INV-MW-user-cache-eviction-no-resurrect** `InvalidateUserTokenCache(userID)`, the
  per-user eviction primitive (third alongside INV-MW-07's `InvalidateTokenCacheByHash` and
  `InvalidateAllMachineTokenCache`), drops every human cache entry of the user: the user's
  own sessions and PATs, and impersonation sessions the user started (`ImpersonatedBy` =
  userID), matching the `user_id OR impersonated_by` union of
  `ListSessionTokenHashesForUser` it stands in for when that listing fails. It never
  matches machine entries, another user's entries, or the impersonation target's own
  sessions, and user ID 0 is a no-op. A slow-path validation already in flight cannot
  re-cache a dropped entry: `userEvictedAt` makes `cacheSetValidatedGen` refuse any entry
  whose user or impersonator was evicted at or after the validation began, and a tie
  (same clock tick) goes to the eviction. A validation that begins strictly after the
  eviction caches normally. Why: ERRLOSS-REVOKE-1 (#3777) fail-closed fallback for the
  session-revocation paths in internal/core (session_eviction.go); REVIEW-3777-DEEP-1
  found the strict `After` tie fail-open (flaky on darwin) and the impersonation gap.
  Guard: `user_cache_eviction_test.go` (`TestInvalidateUserTokenCache_*`: `_DropsOnlyThatUsersEntries`,
  `_DropsInFlightPositiveForUncachedKey`, `_TieGoesToEviction`,
  `_CoversImpersonationSessionsTheUserStarted`, `_ZeroUserIsANoOp`).
