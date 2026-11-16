- **INV-STORE-gorm-identifier-caller-input-bound** Every caller- or tenant-influenced
  string a list-query builder forwards to gorm (`ListSecrets`, `ListUsers`,
  `GetAuditLogs`: Search, Username, Email, Type, Classification, CreatedBy, Action(s),
  Resource, IPAddress, RequestID, ActorUsername, ResourceType and the project scope)
  reaches the database only as a **bind variable**, never interpolated into the SQL
  statement text as an identifier or clause; the emitted statement is always a single
  statement (no stacked `;`); when a project scope is requested the `project_id`
  predicate is present with the id bound; and the SQLite and PostgreSQL statements
  reduce to the same structural skeleton (keyword sequence + bind count) modulo the
  dialect classes enumerated in `gorm_identifier_EXPECTED_DIFFERENCE.md`. Why: GM1
  gorm-identifier fuzz campaign (2026-11-15) — identifier/clause/`Order`/`Select`/
  `Joins`/`Group` sinks are the SQL-injection and cross-tenant-leak surface of the list
  APIs; Keyorix parameterises them, and this pins that it stays so. Guard:
  `FuzzGormListSQLShape` (DryRun capture of `db.Statement.SQL`+`Vars` on both dialects,
  INJ/SHAPE/TENANT/DIFF checks) and `TestGormIdentifierOracle_RedGreen`
  (`gorm_identifier_fuzz_test.go`; each check proven to fire on a planted interpolated
  `Order`/`Where`, a stacked statement, a dropped tenant predicate and a cross-backend
  structural divergence, and to stay green on the real builders). The result side —
  a project-scoped `ListSecrets` never returns another project's row — is enforced on a
  live migrated store (SQLite + Postgres) by `FuzzGormListTenantIsolation` and
  `TestGormTenantIsolation_RedGreen` (`gorm_tenant_isolation_fuzz_test.go`; the
  cross-tenant assertion proven to fire on a no-scope leak).
