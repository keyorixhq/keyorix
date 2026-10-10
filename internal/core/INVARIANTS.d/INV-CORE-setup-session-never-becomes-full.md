- **INV-CORE-setup-session-never-becomes-full** A login that owes both account-setup steps (a
  restricted account with no second factor under `security.require_mfa`: recover-admin,
  one-time-password user, forced reset, pending first login) mints a `models.Session.SetupOnly`
  session whose absolute lifetime is at most `SetupSessionTTL` from login; refresh carries the
  flag and never extends the ceiling; and `EndSetupSessionIfComplete` revokes every session of
  the account once nothing is owed, so the next login is a normal two-step MFA login. Why: #3024.
  Guard: `server/http/account_setup_session_ttl_test.go:TestAccountSetup_SetupSessionIsShortLived`,
  `TestAccountSetup_LiveSessionForcedReset`,
  `server/http/account_setup_gate_test.go:TestAccountSetup_EitherOrder_EndsInMFALogin`.
<!-- section: Account-state / exhaustiveness -->
