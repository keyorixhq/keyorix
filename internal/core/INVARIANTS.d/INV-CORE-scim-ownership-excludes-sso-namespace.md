- **INV-CORE-scim-ownership-excludes-sso-namespace** A SCIM token acts only on accounts SCIM
  provisioned: `scimManaged` is "a stored external id that is NOT in the `sso:` namespace", and
  every SCIM user operation (get, userName-filter list, page list, replace, patch, deprovision)
  and every SCIM group member add (create, replace, patch) goes through it (`scimManaged`,
  `scimManagedMember`, `SCIMManaged` in the handler). An `sso:` id is written by
  `resolveSSOUser` when a native account is claimed by verified email and by
  `provisionSSOUser` for JIT accounts; neither is SCIM's, and the row cannot tell them apart,
  so both are out of scope. The marker stays durable because `ProvisionSCIMUser` refuses an
  `sso:` externalId (`ErrSCIMReservedExternalID`) and an SSO link never rewrites a non-empty
  external id. A refused id answers exactly like a missing one (same 404). Why: #3418 (a
  native administrator claimed through SSO became readable, editable, deactivatable and
  deletable by the SCIM token). Guard: `server/http/handlers/scim_ownership_matrix_test.go`
  `TestSCIM_OwnershipMatrix` (every SCIM operation x native / SSO-claimed native / SCIM-created /
  SCIM-created then SSO-linked; plus a completeness check over the SCIM routes),
  `scim_sso_claimed_ownership_test.go`.
  **Not covered**: a SCIM create without an externalId stores an empty id, so SCIM cannot
  manage that account afterwards (pre-existing; not changed here).
