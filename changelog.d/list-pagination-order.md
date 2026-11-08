### Fixed
- **Paginated user, group and secret lists have a stable order.** `ListUsers` and
  `ListSecrets` had no `ORDER BY` on the paged query and `ListGroupsPage` ordered by name
  only, so on PostgreSQL the row order could change between pages when the planner's
  statistics changed, repeating some rows and skipping others in a page-by-page walk. The
  queries now end in an `id` tiebreak (existing primary sort keys are unchanged). Regression
  tests walk the pages on SQLite and, with `KEYORIX_TEST_PG_DSN` set, on PostgreSQL with an
  `ANALYZE` between pages.
