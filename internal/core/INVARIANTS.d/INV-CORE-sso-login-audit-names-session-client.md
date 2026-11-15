- **INV-CORE-sso-login-audit-names-session-client** An SSO login (`CompleteSAML`,
  `CompleteSSO`) writes its `auth.sso_login` event, its `auth.sso_login_session_failed`
  event, the `auth.sso_jit_provisioned` event of the account it creates, and the reconcile
  events it produces (`auth.sso_groups_synced`, `auth.sso_roles_synced`,
  `auth.sso_reconcile_refused`, `auth.sso_reconcile_last_admin_removal_refused`), with the
  same client address the session row gets: the `ip` argument the handler passes,
  `clientIP(r)` after the `ClientIP` middleware (the forwarded client behind a trusted
  proxy, the TCP peer otherwise), as the password login's `auth.login` does. Never an empty IP
  and never `r.RemoteAddr`. The SAML per-IP budget (`sso_begin`, spent on `BeginSAML`; the ACS is
  budget-exempt) is keyed by the same value. Why: #2934 (b) — the session IP was fixed in #2919,
  the login event still carried no address at all. Guard: `server/http/handlers`
  `sso_login_audit_client_ip_test.go`
  (`TestCompleteSAML_LoginAuditRecordsTheSessionsClientIPBehindTrustedProxy`, the OIDC sibling,
  `TestBeginSAML_BudgetKeyIsTheForwardedClientBehindTrustedProxy`),
  `TestLoginHandlers_NeverPassRawRemoteAddrToALoginCall`; the account-change events:
  `server/http/handlers` `sso_jit_audit_client_ip_test.go`
  (`TestCompleteSAML_JITProvisionAuditRecordsTheForwardedClientBehindTrustedProxy`, the OIDC
  sibling) and `internal/core` `sso_account_events_client_ip_test.go`
  (`TestCompleteSAML_JITAndReconcileEventsNameTheClientIP`,
  `TestCompleteSAML_ReconcileRefusalEventsNameTheClientIP`,
  `TestCompleteSSO_ReconcileEventsNameTheClientIP`). **Not covered**: the OIDC JIT event is
  pinned only through the handler; no core-level test drives an OIDC login that provisions.
