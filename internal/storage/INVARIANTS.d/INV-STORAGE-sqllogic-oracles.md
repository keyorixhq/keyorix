- **INV-STORAGE-sqllogic-oracles** The `internal/storage/sqllogicfuzz` harness
  holds four metamorphic/differential oracles over the production GORM data
  layer, and each is load-bearing (watched red, not just green). (1) **TLP**: for
  any predicate `p`, the row set of a table equals `rows(p) ⊎ rows(NOT p) ⊎
  rows(p IS NULL)` on the modernc-SQLite dialector. (2) **NoREC**: `COUNT(*)
  WHERE p` equals `SUM(CASE WHEN p THEN 1 ELSE 0 END)` over a derived table.
  (3) **Cross-dialect**: the same GORM query over the defined common subset
  (integer/ASCII-text columns; `= <> < <= > >=` and `+ - *` on integers; `= <>`
  on text; `AND/OR/NOT`; `IS [NOT] NULL`) returns the same row-id *set* on
  modernc-SQLite and PostgreSQL. (4) **Injection-structure**: a value passed to
  a parametrised GORM builder (`Where ?`, map, struct, `IN`, `Not`) never
  changes the DryRun prepared-statement text and never appears in the SQL text.
  Guard: `internal/storage/sqllogicfuzz` Fuzz targets `FuzzTLP`, `FuzzNoREC`,
  `FuzzCrossDialect`, `FuzzGormInjectionStructure`, each paired with a red/green
  proof — `TestTLP_RedGreen` (two-way partition drops the NULL rows),
  `TestNoREC_RedGreen` (a NULL-as-TRUE count overcounts), `TestCrossDialect_RedGreen`
  (divide-by-zero diverges: SQLite NULL vs PostgreSQL error), and
  `TestInjectionStructure_RedGreen` (an interpolated `WHERE`/`ORDER BY` fires the
  oracle). The cross-dialect targets skip cleanly without `KEYORIX_TEST_PG_DSN`.
  **Not covered**: result ordering, NULL ordering, text collation, LIKE, integer
  division/modulo and divide-by-zero (all deliberately outside the common
  subset); JOINs, subqueries, aggregates, window functions and any predicate the
  bounded-depth generator cannot express; row *values* (only row-id membership
  and counts are compared); and runtime SQL safety on any specific driver (the
  injection oracle verifies statement-structure invariance, not execution-time
  escaping).
