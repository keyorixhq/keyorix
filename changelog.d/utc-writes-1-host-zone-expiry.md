### Fixed
- **Session lifetime ceilings and a passkey's last-used time are stored in UTC on a server whose clock is not UTC (SQLite).**
  On SQLite a timestamp is stored as text in the zone it carries. A new session's
  last-seen time and absolute lifetime ceiling (at login, for a setup-only session, and when
  the session is refreshed) and a passkey's last-used time were stored in the host zone,
  inconsistent with every other expiry column; they are now written in UTC, and the bounds
  of the stale-token and stale-machine-credential counts are normalised to UTC as well.
  Expiry checks compare instants in the server, so nothing expired early or late.
  PostgreSQL stores an instant and was never affected. Rows already stored in the host
  zone are not rewritten by the upgrade: a session ceiling becomes UTC at its next refresh.
