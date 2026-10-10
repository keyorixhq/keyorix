- **INV-CORE-login-reservation-identifiable** A per-IP login-budget reservation
  (`ReserveLoginAttempt`) is identified by a key core generates BEFORE the write, and the
  storage write is idempotent per key (`login_attempts.reservation_key`, unique; ON CONFLICT DO
  NOTHING, id read back by key). Core retries a failed reservation write exactly once with the
  SAME key. So a write that landed but reported an error is recovered (released when the login
  delivers a session, kept when it fails), a write that failed once is still counted, and no
  reservation is ever counted twice. Never under-count: a failed credential always leaves
  exactly one row; a write that keeps failing is the documented fail-open case. Why: the
  exhaustive login-op sweep on #2956 (`ReserveLoginAttempt#1/effect-then-error` on
  /auth/login, /auth/mfa/verify, /auth/webauthn/login/finish): the row landed with no handle,
  so a delivered login stayed counted. Guard: `server/faultops`
  `TestLoginEffectThenErrorTuples_PassEveryOracleWithoutARow`; `server/http/handlers`
  `login_budget_identifiable_reservation_test.go`; `internal/storage/store`
  `TestReserveLoginAttempt_IsIdempotentPerKey`; `internal/storage`
  `TestLoginAttemptReservationKey_AddedOnUpgrade`.
