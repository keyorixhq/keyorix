### Fixed
- **Expiry and last-used timestamps are stored in UTC on a server whose clock is not UTC (SQLite).**
  SQLite compares these columns as text, so a value stored in the host's zone ordered against
  UTC "now" by wall clock, and could expire hours early or late. Now written in UTC: a
  session's absolute lifetime ceiling (at login and when it is refreshed), the 10-minute
  OIDC and SAML login state, and a one-time password's expiry. A personal access token,
  machine credential or session's "last used / last seen" stamp, and a passkey's last-used
  time, were also stored in the host zone, and the "only move forward" update could replace
  a newer stamp with an older one; they are now UTC, as are the bounds of the stale-token
  counts that read them. PostgreSQL stores an instant and was never affected. Rows already
  stored in the host zone are not rewritten by the upgrade: a session ceiling becomes UTC at
  its next refresh, and login states and one-time passwords are short-lived. An existing
  last-used stamp on a host east of UTC can stay unchanged for up to the zone offset (nine
  hours for Tokyo) before a new use replaces it; no access decision reads these stamps.
