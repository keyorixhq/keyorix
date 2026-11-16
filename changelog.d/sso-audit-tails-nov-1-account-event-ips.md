### Security
- **SSO account-change audit events name the client.** `auth.sso_jit_provisioned` and the group/role reconcile events (`auth.sso_groups_synced`, `auth.sso_roles_synced`, `auth.sso_reconcile_refused`, `auth.sso_reconcile_last_admin_removal_refused`) of a SAML or OIDC login now record the same client IP as the login's session (the forwarded client behind a configured trusted proxy); they used to record none. Guarded by `internal/core/sso_account_events_client_ip_test.go` and `server/http/handlers/sso_jit_audit_client_ip_test.go`.

### Changed
- The Audit page shows readable labels for `auth.sso_login_session_failed`, `auth.sso_reconcile_refused` and `auth.sso_reconcile_last_admin_removal_refused` instead of the humanized event name.
