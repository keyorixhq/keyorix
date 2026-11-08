- **INV-STORE-paged-lists-total-order** A list query paged with `.Offset(...)` is ordered by a
  total order: its last sort key is the unique `id`, after any filter-specific keys
  (`deleted_at DESC`, `expiration ASC`, `name ASC`). Without it the rows of page N follow the
  query plan, PostgreSQL changes plan once statistics exist, and a client walking the pages
  sees a row twice and misses another. `ListSecrets` with `ExpiresBefore` over equal
  expirations repeated one row 19 times in a 40-row walk before `secret_nodes.id` was appended.
  Why: #4022. Guard: `TestOffsetPagedQueriesEndInUniqueIDOrder` (every `.Offset(` function in
  `internal/storage/store` and `internal/encryption` also orders by a final `id` key;
  `TestOffsetPagedQueriesGuard_Calibration` shows it red on unordered and non-unique orders),
  `TestListPagination_WalkReturnsEveryRowOnce_SQLite` and `_Postgres` (page walks of
  `ListUsers`, `ListSecrets`, `ListGroupsPage`; the `ListUsers` and `ListSecrets_ExpiresBefore`
  legs are red-proven on PostgreSQL, the others are defensive).
