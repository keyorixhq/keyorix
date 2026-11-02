### Security
- **Updating a custom role can no longer bring back a role deleted at the same time.** `UpdateRole` stored the role with a full-row `Save`, which re-inserted a role a concurrent delete had just removed (same id, stale name and description). It now writes only `description` and `assignable_scope` for that id, and a role deleted in between makes the update fail with "role not found" instead. Covered by race tests on SQLite and Postgres.

### Changed
- **Removed the unused `UpdateDynamicSecretLease` storage method.** Nothing has called it since lease renew and revoke moved to column-scoped writes (#2825). The full-row write ledger rows for break-glass, legal hold and users now say whether a stale write could affect access.
