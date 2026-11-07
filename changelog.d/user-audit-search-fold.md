### Fixed
- **User search and the audit-log actor filter match case-insensitively in the Unicode sense on both backends.**
  `GET /users` `search` (username, email and display name) and the audit-log actor filter used
  `LIKE` / `ILIKE` / `LOWER()`, which fold ASCII only on SQLite and are case-sensitive or
  locale-dependent on PostgreSQL, so the same search returned different rows per backend
  (for example `ünal` versus `ÜNAL`). Both now use the shared fold already applied to the
  username and email filters and to secret search; `%`, `_` and `\` stay literal.
