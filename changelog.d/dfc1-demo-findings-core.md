### Documentation
- **The `inactive` users filter is described as the server applies it.** The OpenAPI `filter` parameter of `GET /api/v1/users` and the `ListUsersRequest.filter` comment now say: no login in the last 30+ days, and an account that has never logged in counts as inactive only once it is 30+ days old (judged by its creation date). Text only, no behaviour change; the web types and the pb files are regenerated.

### Testing
- **Request-side MFA-reset audit outage test.** `TestRequestMFAReset_AuditOutage_SharedAuditUnavailable503` joins the approve one: a request whose audit row the audit log refuses answers 503 `audit_unavailable` and records no request.
