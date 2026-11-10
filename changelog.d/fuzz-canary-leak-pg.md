### Testing
- **Canary leak fuzz targets for PostgreSQL.** Plant a canary secret and assert it never appears in errors, logs, stdout/stderr, metrics, DB error DETAIL, gRPC status or HTTP bodies/headers, across core, HTTP, gRPC, panic-dump and CLI paths. PG-gated: they skip without `KEYORIX_TEST_PG_DSN`.
