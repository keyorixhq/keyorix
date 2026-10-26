- **INV-CORE-sso-first-login-clear-scim-owned-only** An IdP sign-in (`CompleteSSO`,
  `CompleteSAML`) moves an account out of `pending_first_login` only through
  `completeIdPFirstLogin` (sso.go), and only for a `scimOwned` account (bare externalId, so the
  IdP owns the credential and the stored password is a discarded random one). A local-password
  account keeps `pending_first_login` however it signs in, including one an SSO login claimed by
  email: the claim stamps the `sso:` scheme, which `scimOwned` refuses. The clear runs after every
  login gate (suspended/deprovisioned, lockout, group/role reconcile, password expiry) and before
  `mintSession`; it is a conditional `SetAccountStateIfMatches` (pending -> active) committed with
  its `scim.first_login_completed` audit row (access granted, so fail closed), and a state that
  moved meanwhile is re-read and a blocked account refused. Session, MFA and expiry rules are not
  touched. Why: #3655 (a SCIM user's first SSO login was stuck in a change-password-only session
  that needed a password nobody knew). Guard:
  `scim_sso_first_login_test.go:TestSCIMUserFirstSSOLogin_ClearsPendingFirstLogin` (SQLite, plus
  `_Postgres` pg-gated): clears for SCIM, keeps for a claimed local account, blocks suspended and
  deprovisioned.
