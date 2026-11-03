# Backup, restore and moving between backends with large databases

This page states what was verified for databases with millions of rows, which limits apply
and what a failure leaves behind. It gives no timings: those depend on the host and are in the
pull request that added the check (`scripts/migrate/scale-check.sh`).

## Directions that are verified

There is no separate migration tool. Moving between backends is `admin backup` on the source
and `admin restore` into a config that points at an **empty** database of the target backend
([SELF_HOSTING.md](../SELF_HOSTING.md#moving-from-sqlite-to-postgres)). Three combinations are
exercised with real binaries, each compared table by table (row count and checksum) against
the source and followed by `verify-audit`:

| From | To | Checked by |
|---|---|---|
| SQLite | SQLite | `scripts/migrate/scale-check.sh` |
| SQLite | PostgreSQL | `scripts/migrate/scale-check.sh`, `scripts/migrate/sqlite-to-pg-check.sh` |
| PostgreSQL | SQLite | `scripts/migrate/scale-check.sh`, `scripts/migrate/sqlite-to-pg-check.sh` |

PostgreSQL to PostgreSQL is not checked at scale. `sqlite-to-pg-check.sh` goes further for both directions: the audit chain verifies against a
checkpoint exported before the first move (no new genesis), the retention anchor is
byte-identical, and users, roles, shares, MFA, break-glass history, machine tokens and
dynamic-secret configs work on the other side. The container and Helm variants of this move are
pending a run on the e2e VM.

## Memory

`admin backup`, `admin restore` and `admin verify-audit` read and write tables row by row (or in
fixed batches), so their peak memory does not depend on how many rows a table has. This is what
`scale-check.sh` measures at three sizes: peak resident memory at the largest size should be
within the noise of the smallest. If you see memory growing with the database, that is a bug:
report it with the command and the table sizes.

Disk is what grows. A restore unpacks the archive into a staging directory under `$TMPDIR`
before it loads anything, so `$TMPDIR` needs room for the archive's uncompressed contents (the
pre-flight check estimates four times the archive size and runs on that directory). Point
`TMPDIR` at a large filesystem for a large restore. On SQLite the restored database is also built
beside the live path (`<db>.restoring-<timestamp>`) before it is installed, so that filesystem
needs room for a second copy of the database.

## Limits

- **Per-table and total size of an archive.** `admin restore` refuses an archive in which one
  table's data is larger than `--max-entry-bytes` (default 1 GiB uncompressed) or whose total is
  larger than `--max-total-bytes` (default 2 GiB). They exist so that a crafted archive cannot
  fill the disk before its signature is checked. The audit log is normally the first table to
  reach the default. For an archive you made yourself, raise both:

  ```sh
  keyorix-server admin restore --input backup.tar.gz \
    --max-entry-bytes 17179869184 --max-total-bytes 34359738368
  ```

- **Backup consistency.** On SQLite a backup needs the server stopped; on PostgreSQL it reads
  through one snapshot and works beside a live server (see `admin backup --help`). A larger
  database keeps that lock or snapshot for longer.
- **One transaction.** A PostgreSQL restore loads everything in one transaction, so the database
  holds either none of the archive's rows or all of them.

## If a large restore or backup is killed

Verified on a large data set with SIGTERM and SIGKILL (`scripts/migrate/scale-kill-check.sh`):

| Killed during | Left behind | Way forward |
|---|---|---|
| `admin restore` into SQLite, while loading | staged files beside the live paths (`*.restoring-*`); no database at the live path, no installed key files, no journal; `verify-audit` on the target does not pass | run `admin restore` again: it removes the leftovers and loads from scratch |
| `admin restore` into PostgreSQL, inside the load transaction | the journal and staged key files; no installed key files; PostgreSQL rolls the transaction back, so the tables hold no archive rows | `admin restore --recover` (rolls back), then `admin restore --overwrite-existing` again: the restore had already created the empty schema, so a plain re-run is refused as a populated target. A plain re-run is also refused while the journal exists |
| `admin backup` | a partial archive file at `--output` | delete it and run the backup again: a backup never overwrites an existing file, and a restore from a partial archive is refused before it changes anything |

Details of every restore step are in [restore-failure-modes.md](restore-failure-modes.md).
