### Fixed
- **Key-directory lock refusals blame a live server only when another process really holds the lock (#3742).** `admin encryption rotate`, `rotate-kek`, `migrate-provider`, the auth-encryption commands and the migrate-backup cleanup no longer say "stop the running server" for a missing key directory or a permission error; they report the real cause.
- **`POST /secrets/bulk-delete` reports an audit-log outage per item as "could not record the change in the audit log; nothing was changed, retry" instead of "internal error" (#3912).** Nothing is deleted for that item and the response status is unchanged.
- **`POST /auth/end-impersonation` with a personal access token answers 403 instead of 500 "session not found" (#3465).**
