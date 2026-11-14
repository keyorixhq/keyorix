- **INV-CORE-sso-session-mint-failure-retriable-audited** When an SSO login has passed every
  gate (JIT provisioning and group/role reconcile included) and its session insert then fails,
  the login is refused with no session, the account and its reconciled grants are KEPT (class C,
  `docs/atomicity-exempt.tsv` `JIT:(*KeyorixCore).CompleteSAML`, not one transaction), and
  exactly one failed `auth.sso_login_session_failed` event names the account and the client
  (`auditSSOLoginSessionFailed`; the storage error is logged, not audited). The state is
  retriable: the next ACS for the same identity reuses the account by its `sso:` external id and
  ends with exactly the grants a fault-free first login gives (no second user, no extra role or
  membership). Why: #2839 item 1 tail — nothing recorded that the login had failed after
  `auth.sso_jit_provisioned`. Guard: `sso_login_session_failed_test.go` (real SQLite under
  faultstorage: `TestCompleteSAML_SessionInsertFailsAfterJIT_RefusedKeptAndAudited`,
  `TestCompleteSAML_RetryAfterSessionInsertFailure_ConvergesOnCleanLogin`, compared against a
  fault-free world; `TestCompleteSSO_SessionInsertFailure_Audited`).
