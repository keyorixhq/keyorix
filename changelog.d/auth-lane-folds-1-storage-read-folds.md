### Fixed
- **Impersonation answers a database read outage with "retry", not with a verdict.** A
  failed read of the impersonating admin (re-checked on every request made with an
  impersonation session) answered 401 and the session's token was cached as invalid; it now
  answers 503 with `Retry-After` (gRPC `Unavailable`), and a failure to re-check the admin's
  authority is no longer remembered for 60 seconds as a refusal. `POST
  /api/v1/admin/impersonate` and `POST /api/v1/auth/end-impersonation` answer a failed
  read with 503 `storage_unavailable` instead of 404 / 500. A deleted admin, target or
  session is still refused as before.
