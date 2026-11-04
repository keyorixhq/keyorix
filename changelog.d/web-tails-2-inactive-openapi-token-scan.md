### Changed
- **Inactive-user filter documented by its real rule.** The `filter=inactive` description of `GET /api/v1/admin/users` in the OpenAPI spec now says a user is inactive when the last login, or for an account that never logged in its creation date, is 30+ days old (the rule since #3740). Description only, no schema change.
- **Web session-token guard scans for opaque tokens.** `sessionTokenNeverPersisted.test.ts` (INV-WEB-03) now also fails on a 32+ char hex or base64 run written to `localStorage`/`sessionStorage`, with a calibration case and a UUID allow-list.
