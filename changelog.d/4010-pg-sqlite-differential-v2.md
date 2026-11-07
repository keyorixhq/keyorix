### Testing

- `FuzzStorageBackendDifferentialV2` runs the same operation sequence against SQLite and PostgreSQL and compares storage error classes, edge-string handling, updates, filtered page walks and secret value bytes. Companion tests compare `ORDER BY` lists and concurrent unique-key races. All of them skip without `KEYORIX_TEST_PG_DSN`. The pre-registration and the outcome of the first campaign are in `docs/fuzzing/pg-sqlite-differential.md`.
