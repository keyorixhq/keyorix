### Security

- **Upgrade note for #3493: SCIM-created rows whose `externalId` starts with `sso:` are no longer SCIM-managed.** `sso:` is the scheme SSO sign-in writes (`sso:<provider>:<sub>`), so since #3493 SCIM refuses to create, read, update, deactivate, delete or group such an account. A SCIM connector that ever sent an `externalId` starting with `sso:` left a row SCIM can no longer deactivate, and an IdP disable or SCIM `active=false` for it revokes nothing: its PATs and sessions live until a Keyorix administrator suspends (`keyorix user suspend --id N`), deactivates (`keyorix user update --id N --active false`) or deletes (`keyorix user delete --id N`) the user, the PAT expires or the session lifetime ends. The inactivity sweep (`keyorix user suspend-inactive --days N`) is on demand only, not scheduled. To list the affected rows, join `external_id` to the `scim.user_provisioned` audit rows (a bare `external_id LIKE 'sso:%'` would also list every account SSO itself claimed or created); the statement is the same on SQLite and PostgreSQL and was run on both (`TestUpgrading6vCheckQuery_FindsOnlySCIMCreatedSSORows`, the PostgreSQL leg against a kpg database):

  ```sql
  SELECT u.id, u.username, u.email, u.external_id, u.account_state
  FROM users u
  JOIN audit_events a
    ON a.event_type = 'scim.user_provisioned'
   AND a.description LIKE 'SCIM provisioned user ' || CAST(u.id AS TEXT) || ' (%'
  WHERE substr(u.external_id, 1, 4) = 'sso:'
    AND u.deleted_at IS NULL
  ORDER BY u.id;
  ```

  No rows means nothing to do; the check only sees accounts whose audit row is still within audit retention. Details: `docs/UPGRADING.md` section 6v, `docs/CONFIGURATION.md` "Offboarding an SSO / JIT account", threat model SCIM-7.

### Documentation

- **SCIM / SSO offboarding docs corrected (SCIM-JIT-TAILS-1).** The offboarding steps no longer pass the deprecated, ignored `--by` flag and now list the deactivate step (`user update --active false`, `PUT /api/v1/users/{id}`) next to suspend and delete. The SCIM and SSO threat model no longer lists #3494 as an open defect: SCIM user and group handlers classify storage errors by sentinel (404 only for a positively absent or not-SCIM-managed object, 500 with a generic detail otherwise).

### Testing

- **SCIM storage-fault table extended to the list endpoints, and the JIT offboarding gap pinned.** `TestSCIM_ListStorageError_Is500NotNotFound` covers `GET /Users` and `GET /Groups` (paged and filtered): any storage error is a 500 SCIM error body, never 404 or an empty 200, never the driver text. `TestJITOffboardingGap_PATSurvivesSCIMDeactivation` pins the documented behaviour that a JIT-provisioned user's PAT keeps working after SCIM `active=false` and `DELETE` for its external id (both refused as not SCIM-managed); a future offboarding design that changes it must update the docs and rewrite the test.
