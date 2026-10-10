- **INV-HTTP-login-budget-counts-failures-only** The shared per-IP login budget counts
  failures, not logins. Every login-family endpoint still reserves its slot BEFORE the
  credential check (INV-HTTP-19 is unchanged), but a request that DELIVERS a session —
  `Login`, `VerifyMFA`, `FinishWebAuthnLogin`, `FinishWebAuthnPasswordlessLogin`,
  `RefreshToken`, `ConsumeSetup`, plus a successful `BeginWebAuthnLogin` (it only resolves the
  bearer challenge a correct password earned) — returns its own slot via `returnLoginSlot`,
  and only on that path. A wrong credential, a refused request and a post-verdict storage
  fault (#2880/#2894) keep the slot. The step that does not finish its flow keeps its slot
  too (the password step of an MFA login; `BeginWebAuthnPasswordlessLogin`, which is callable
  cold by anyone and must stay bounded, G1), so one login flow costs at most one slot. The
  count is the persisted `login_attempts` table, so a restart does not reset it. Why: #2936
  (Andrei, 2026-10-10: "count failures only") — charging successes let a handful of ordinary
  MFA logins from one IP lock everybody behind it out for 15 minutes, surviving a restart.
  Guard: `login_budget_count_failures_test.go`
  (`TestLoginBudget_SuccessfulLoginsDoNotConsumeTheBudget`,
  `TestLoginBudget_MFALoginConsumesExactlyOneSlot`,
  `TestLoginBudget_SuccessfulRefreshesDoNotConsumeTheBudget`, and the calibrations
  `TestLoginBudget_FailuresStillLockAtTheThreshold`,
  `TestLoginBudget_FailureCountSurvivesRestart`). Host-side override:
  `keyorix-server admin clear-login-lockout` (audited, `server/admin/login_lockout.go`).
  **Not covered by a test**: the WebAuthn second-factor and passwordless flows' one-slot cost
  (the handler package's WebAuthn fixtures cannot produce an assertion that verifies, see
  `internal/core/webauthn_login_attempt_accounting_test.go`), so those two paths rest on the
  same `returnLoginSlot` call placement the TOTP and password tests exercise.
