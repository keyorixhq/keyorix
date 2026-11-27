### Documentation
- **SQLite to PostgreSQL growth path verified.** `docs/operator/drill-sqlite-to-postgres.md` now carries the verified matrix (commit-pinned) of `scripts/migrate/sqlite-to-pg-check.sh`, including the non-empty-target and wrong-master-password refusals.

### Testing
- **Migration check script repaired and extended.** `scripts/migrate/sqlite-to-pg-check.sh` sets `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport` for its loopback dynamic-secret target (the dynamic-secret create step failed without it), `migratecheck` no longer compares `system_metadata.service_accounts_purge_v1` (the target writes it itself), and three refusal legs were added.
