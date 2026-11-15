- **INV-CORE-sso-login-audit-names-session-client** An SSO login (`CompleteSAML`,
  `CompleteSSO`) writes its `auth.sso_login` event, and its `auth.sso_login_session_failed`
  event, with the same client address the session row gets: the `ip` argument the handler
  passes, `clientIP(r)` after the `ClientIP` middleware (the forwarded client behind a trusted
  proxy, the TCP peer otherwise), as the password login's `auth.login` does. Never an empty IP
  and never `r.RemoteAddr`. The SAML per-IP budget (`sso_begin`, spent on `BeginSAML`; the ACS is
  budget-exempt) is keyed by the same value. Why: #2934 (b) — the session IP was fixed in #2919,
  the login event still carried no address at all. Guard: `server/http/handlers`
  `sso_login_audit_client_ip_test.go`
  (`TestCompleteSAML_LoginAuditRecordsTheSessionsClientIPBehindTrustedProxy`, the OIDC sibling,
  `TestBeginSAML_BudgetKeyIsTheForwardedClientBehindTrustedProxy`),
  `TestLoginHandlers_NeverPassRawRemoteAddrToALoginCall`. **Not covered**: the JIT-provision and
  reconcile events (`auth.sso_jit_provisioned`, `auth.sso_*_synced`, `auth.sso_reconcile_*`)
  still carry no IP; they describe account changes, not the request.
