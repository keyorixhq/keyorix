### Fixed
- **Expiry and last-used timestamps are stored in UTC on a server whose clock is not UTC (SQLite).**
  On SQLite a timestamp is stored as text in the zone it carries. A session's absolute
  lifetime ceiling (at login and when it is refreshed), the 10-minute OIDC and SAML login
  state, and a one-time password's expiry were stored in the host zone, inconsistent with
  every other expiry column; they are now written in UTC. Their expiry checks compare
  instants in the server, not stored text, so they did not expire early or late. A personal access token,
  machine credential or session's "last used / last seen" stamp, and a passkey's last-used
  time, were also stored in the host zone, and the "only move forward" update could replace
  a newer stamp with an older one; they are now UTC, as are the bounds of the stale-token
  counts that read them. PostgreSQL stores an instant and was never affected. Rows already
  stored in the host zone are not rewritten by the upgrade: a session ceiling becomes UTC at
  its next refresh, and login states and one-time passwords are short-lived. An existing
  last-used stamp on a host east of UTC can stay unchanged for up to the zone offset (nine
  hours for Tokyo) before a new use replaces it; no access decision reads these stamps.
