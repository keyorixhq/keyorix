- **INV-CORE-sso-reconcile-refusal-no-session-audited** A SAML login (`CompleteSAML`) whose
  IdP group/role reconcile did not fully apply mints NO session, returns an error wrapping
  `ErrSSOReconcileIncomplete` whose `Error()` is exactly one client-safe `SSOMsg*` text, and
  writes exactly ONE failed audit event naming every step that failed and the counts that had
  already applied (they are not rolled back: class C, `docs/atomicity-exempt.tsv`
  `JIT:(*KeyorixCore).CompleteSAML`). The event is `auth.sso_reconcile_last_admin_removal_refused`
  when one failed step is a removal the install's last-admin guard refused
  (`storage.ErrWouldStrandLastAdmin`, which `guardLastGlobalAdminMembership` and
  `RemoveGlobalAdminRoleGuarded` both wrap), else `auth.sso_reconcile_refused`. A groups
  attribute that is PRESENT but empty reconciles to zero; an ABSENT one is a no-op
  (`ports.SAMLAssertion.GroupsPresent`). Why: #2839/#2903 — a failed revocation used to ride
  into a session, a lone failed removal left no audit record, a partial change was recorded
  as a successful sync, and an empty assertion skipped reconcile entirely.
  Guard: `saml_reconcile_refusal_test.go` (real SQLite: persisted state and audit rows read
  back), `saml_jit_class_c_test.go`, `internal/saml`
  `TestExtractAssertion_GroupsPresenceIsDistinctFromEmptiness`, `server/http/handlers`
  `TestIsSafeSSOError_ReconcileRefusals`, `server/admin`
  `TestPerformRecoverAdmin_SSOOnlyLastAdminWithNoPassword` (the documented way back works).
  **Not covered**: the OIDC path (`CompleteSSO`) still discards the reconcile error until
  #2907 lands; project-level last-admin refusals are audited as the generic refusal (a global
  admin can repair a project, so no out-of-band recovery is needed).
