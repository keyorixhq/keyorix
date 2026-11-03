### Fixed
- **Auth endpoints answer a database read outage with "retry", not with a verdict.**
  `GET /api/v1/auth/profile` answered a failed read of the caller's own account with
  404 "User not found"; it now answers 503 with `Retry-After` and the code
  `storage_unavailable` (a deleted account and a machine credential still get 404).
  `POST /api/v1/auth/mfa/stepup` answered the same read failure, which happens before any
  code is checked, with 401 "user not found"; it is now 503 with `Retry-After`, and the
  failed attempt no longer counts against the IP's login budget.
  `POST /auth/setup/consume` with an invitation link still answers a storage fault with the
  same response an invalid link gets (a different status would confirm the link), but the
  audit log now records it as `setup_token.consume_error` (a fault; the link still works)
  instead of `setup_token.consume_failed` (an invalid-link attempt).
- **A used MFA recovery code's `used_at` is stored in UTC on a server whose clock is not UTC
  (SQLite).** It was stored in the host zone. PostgreSQL was not affected; existing rows are
  not rewritten.
