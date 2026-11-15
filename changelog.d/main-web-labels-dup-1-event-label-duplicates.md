### Fixed
- Web: removed duplicate `auth.sso_login_session_failed`, `auth.sso_reconcile_refused` and `auth.sso_reconcile_last_admin_removal_refused` keys from the audit event label table (tsc TS1117 broke the web type-check on main). One label per key now, and both eventLabels test files agree on it.
