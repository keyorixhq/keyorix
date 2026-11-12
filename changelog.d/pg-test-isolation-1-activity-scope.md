### Testing
- **Postgres tests that read backend state count only their own backends.** `internal/core` and `internal/storage` run in parallel on one database and tests isolate by schema, which does not separate `pg_stat_activity`: the last-used coalescer's lock-wait probe counted another package's waiter (red in 18 of 30 runs beside a store loop), the cross-replica lock-wait gates could be released by a foreign waiter, and the pipelined-batch `pg_sleep` probe could pick, and terminate, a foreign backend. They now tag their connections (`pgdsn.WithApplicationName`) and filter on `application_name`. `TestSharedDatabaseActivityGuard` fails a test file that queries `pg_stat_activity` or `pg_locks` without such a scope (report-only until the long-reader test is fixed by its own PR). Test-only; no production change.

### Documentation
- **`docs/testing/postgres-tests.md` says why the Postgres-backed packages need a database each, or `-p 1`.**
