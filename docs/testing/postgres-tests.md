# Running the Postgres-backed tests locally

Tests that need a real PostgreSQL skip unless `KEYORIX_TEST_PG_DSN` is set. A
security fix verified on SQLite only has not been verified: run the packages
below against Postgres before you rely on it, not after CI has failed.

## The rules

1. **One database per package.** The packages share a schema and run
   cross-replica tests, so two packages against one database collide. Create a
   database per package and point `KEYORIX_TEST_PG_DSN` at it for that run.
2. **`-p 1 -parallel 1`.** Run one package at a time, one test at a time:
   `go test -p 1 -parallel 1 -count=1 ./internal/core`. (`-count=1` because a
   cached result proves nothing about the database.)
3. **`-timeout 20m` for `internal/core`.** Its Postgres run takes about 12
   minutes; the default 10 minutes kills it.
4. **One heavy package at a time** (`internal/core`, `internal/storage`,
   `internal/storage/store`, `server`, `server/http`): they are large and
   write a lot to the Go work directory.

## Why: one database per package, or `-p 1`

Schema isolation separates rows, not the server's backends, locks or snapshots.
`pg_stat_activity`, `pg_locks`, advisory-lock keys and the xmin horizon are
database-wide, so two packages run in parallel against one database (the nightly
runs `./internal/core/...` and `./internal/storage/...` that way) see each
other's sessions: a lock-wait count, a "no backend left" check, a snapshot age or
a `pg_terminate_backend` over `datname = current_database()` counts, or kills,
the other package's. Run each package on a database of its own, or run the
Postgres-backed packages with `-p 1`. A test that reads backend state must also
be correct on a shared database: tag its connections with
`pgdsn.WithApplicationName(dsn, pgdsn.UniqueApplicationName("kx_x"))` and filter
`pg_stat_activity` on that `application_name` (or one `pid`), and take a lock-key
or database-wide counter test to its own database with `pgdsn.IsolatedDatabase`.
`TestSharedDatabaseActivityGuard` (`internal/testutil/pgdsn`) fails a test file
that queries `pg_stat_activity` or `pg_locks` without such a scope.

## Packages that need a per-package database

| Package | Notes |
|---|---|
| `internal/core` | `-timeout 20m` |
| `internal/storage` | |
| `internal/storage/store` | |
| `internal/auditverify` | |
| `internal/encryption` | |
| `internal/serverguard` | |
| `internal/solewriter` | |
| `internal/rotation` | |
| `server` | |
| `server/admin` | |
| `server/http` and `server/http/handlers` | |
| `server/grpc` and `server/grpc/services` | |
| `server/faultops` | |

The list is every package with a `_test.go` file that reads
`KEYORIX_TEST_PG_DSN` (`rg -l KEYORIX_TEST_PG_DSN --glob '*_test.go'`).

## Skips that are expected on a non-superuser role

A role without `SUPERUSER` (or `GRANT SET ON PARAMETER
session_replication_role`) skips the `session_replication_role = replica`
tests in `internal/storage/store` and says so in the skip message. Set
`KEYORIX_REQUIRE_PG_SUPERUSER=1` to make those a failure instead of a skip.

A skip is a finding when its message does not name a real missing condition.
