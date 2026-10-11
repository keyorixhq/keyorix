- **INV-CORE-login-budget-storage-fallback** The per-IP login budget
  (`IsLoginRateLimited` / `RecordFailedLogin` / `ReserveLoginAttempt` /
  `ReleaseLoginAttempt`) neither fails open nor fails closed on a LoginAttempt
  storage error: it falls back to a bounded in-memory per-IP limiter with the same
  `LoginMaxAttempts` / `LoginWindow`, keyed by the same `CanonicalIP`, per process
  (`login_budget_fallback.go`). Fallback attempts count in addition to stored ones
  and age out with the window; they are never merged into storage. A fallback
  reservation carries `loginFallbackIDBit` so a delivered login's release refunds
  it in memory. Memory is bounded (`loginFallbackMaxIPs` addresses, LRU; per-address
  attempts capped). Every fallback is audited `auth.rate_limit_error`
  (Success=false) and counted (`keyorix_login_budget_fallback_total`); the client
  sees the same 429. Why: Andrei, 2026-10-10 (AUTH-AUDIT-1) — fail-open removed
  the brute-force backstop during any DB fault; fail-closed would lock everyone
  out. The password-reset and SSO-begin budgets still fail open (not covered by
  this decision). Guard: `login_budget_fallback_test.go`
  (`TestLoginBudgetFallback_StorageDownStillEnforcesTheLimit`, `_ADeliveredLoginReturnsItsMemorySlot`,
  `_RecoveredStorageIsAuthoritativeAgain`, `_NoFaultNoChange`, `_IsAuditedAndCounted`,
  `_BoundedUnderManyDistinctIPs`) and
  `server/http/handlers/login_budget_fallback_http_test.go`.
