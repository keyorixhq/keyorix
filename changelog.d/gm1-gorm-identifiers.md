### Testing
- **gorm identifier/clause injection & tenant-isolation fuzzing (GM1).** Added
  `FuzzGormListSQLShape` over the three caller-influenced list builders
  (`ListSecrets`, `ListUsers`, `GetAuditLogs`): it builds each query on the SQLite and
  PostgreSQL dialects in gorm DryRun, captures the parameterised SQL and bind vars off
  `db.Statement`, and asserts that no caller byte reaches the statement text (all
  identifiers/clauses are bound), the statement never stacks, the tenant `project_id`
  predicate is present and bound when a project scope is requested, and the two dialects
  reduce to the same structural skeleton modulo a committed EXPECTED-DIFFERENCE table.
  Added `FuzzGormListTenantIsolation`, which seeds two tenants into a migrated store
  (SQLite and PostgreSQL) and asserts a project-scoped `ListSecrets` never returns
  another project's row under any hostile sort/search/classification/type, with
  error-class agreement across backends. Both targets are red/green-proven
  (`TestGormIdentifierOracle_RedGreen`, `TestGormTenantIsolation_RedGreen`). No
  production code changed — the campaign confirmed Keyorix already binds every
  identifier/sort/filter input it forwards to gorm and scopes every list to its tenant.
