- **INV-CORE-scim-deactivate-revokes-pats** A SCIM deactivation (`UpdateSCIMUser` with
  `active=false`, how Okta and Entra disable a user) revokes every PAT of the user in the same
  transaction as the state change, and the revoked hashes are evicted from the auth cache after
  commit, exactly as SCIM `DELETE` does (#2855). A failed revoke rolls the whole update back. A
  later `active=true` (or an administrator reactivation) brings no PAT back, and an
  administrator suspension is kept through the deactivate and reactivate. Why: #3419. Guard:
  `scim_deactivate_pat_test.go` (`TestUpdateSCIMUser_DeactivateReactivateDoesNotHandBackPATs`,
  `TestUpdateSCIMUser_DeactivateRevokesPATsAndKeepsAdminSuspension`),
  `scim_purge_fault_test.go` `TestUpdateSCIMUser_PATRevokeFaultRollsBackDeactivation`.
