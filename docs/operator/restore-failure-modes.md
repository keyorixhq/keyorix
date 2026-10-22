# What a failed or interrupted restore leaves behind

`keyorix-server admin restore` installs two things that live in different places: the
key-material files (`dek.key`, `kek.salt`, provider files) on the filesystem, and the data
(rows in PostgreSQL, or the SQLite database file). Neither offers a transaction spanning
both, so restore orders its writes so that **the key files and the data change together or
not at all**, and keeps a journal for the one window where a crash could separate them.

This page describes builds that contain the restore journal (changelog: "restore
journal"). Older releases (v0.96.x and earlier) installed the archive's key files
*before* loading the data; for those, see the warning and recovery steps in
[SELF_HOSTING.md §5](../SELF_HOSTING.md).

## The order

1. **Checks.** Archive signature, schema epoch, key-file set, rollback protection. Nothing
   is written.
2. **Stage.** Each archive key file is written and fsynced next to its target as
   `<path>.restoring-<random>`. On SQLite the whole restored database is also built and
   loaded at `<db>.restoring-<timestamp>`. The live files are not touched.
3. **Journal.** `.keyorix-restore-journal.json` is written next to the SQLite database
   (SQLite) or next to the first key file (PostgreSQL), listing every staged file.
4. **Commit point.**
   - PostgreSQL: one transaction empties the target's tables (`--overwrite-existing`),
     loads the archive, runs the mandatory checks (row counts, dangling references),
     resyncs the id sequences and records the journal's token in `system_metadata`.
   - SQLite: the journal itself. It is written only once every staged file is complete.
5. **Install.** Each staged file is renamed over its target; with `--overwrite-existing`
   the original is kept as `<path>.pre-restore-<timestamp>` (for SQLite also its `-wal` and
   `-shm`).
6. **Finish.** The `admin.restore_completed` audit event (and
   `admin.restore_rollback_override` under `--allow-rollback`), the rollback-protection
   witness, removal of the journal, then the automatic `verify-audit`.

## What a failure leaves

| Fails or is killed during | Left behind | What to do |
|---|---|---|
| 1. Checks | nothing | fix the cause, re-run |
| 2. Stage, or a load error (constraint violation, dangling reference, corrupt row) | on an error: nothing; the message ends "nothing was changed". On a `kill -9`/power loss: `*.restoring-*` files beside the live ones, no journal. | re-run. The `*.restoring-*` files of a killed run are inert and can be deleted. |
| 3.-4. Journal written, PostgreSQL transaction not committed | the journal and the staged files; the live key files and rows unchanged | `admin restore --recover` (rolls back) |
| 4.-5. Committed, key files not (all) installed | the journal; the archive's data with some or none of its key files | `admin restore --recover` (rolls forward) |
| 6. Finish | the journal, if it was not removed yet | `admin restore --recover` (rolls forward; may repeat the restore's audit event) |

While the journal exists, the server refuses to start, and `admin backup` and a new
`admin restore` refuse to run:

```
an interrupted `admin restore` left its journal at <dir>/.keyorix-restore-journal.json: the key files and the database may not match until it is resolved. Stop every server on this data, then run `keyorix-server admin restore --recover` (it finishes the restore if its data was committed, and undoes it otherwise)
```

## `admin restore --recover`

```sh
keyorix-server admin restore --recover --config ./keyorix.yaml
```

Takes the same database lock as restore, reads the journal, then:

- **PostgreSQL, token not in the database:** the load never committed. The staged files
  are deleted, the journal removed: `Rolled back: the restore's data was never committed.`
  The key files and rows are what they were before the restore. An
  `admin.restore_recovered` audit event records it.
- **PostgreSQL, token in the database, or SQLite:** the data is committed. The remaining
  staged files are installed (originals moved aside as above), the restore's audit events
  and witness are written, the journal removed, and `verify-audit` runs:
  `Rolled forward: ...`.
- **The database cannot be reached (PostgreSQL):** nothing is changed; fix the connection
  and run it again. Recovery never guesses the direction.
- **No journal:** `No interrupted restore found`, exit 0.

A journal that does not parse is reported, not ignored. Inspect it: it is plain JSON
listing each `path` and its `staged` replacement.

## Audit chain

- A restore that failed or was rolled back writes no audit event of its own (a rollback by
  `--recover` writes `admin.restore_recovered`). The chain is the one that was live.
- A completed restore leaves the archive's chain plus `admin.restore_completed` (and the
  rollback-override event), and `verify-audit` runs automatically. A `BROKEN` verdict
  fails the command but does not undo the restore: the restored data is in place, and
  the archive is the thing to investigate
  ([audit-chain-break-runbook.md](audit-chain-break-runbook.md)).

## SQLite and PostgreSQL compared

Both use the same journal and recovery. The difference is the commit point: PostgreSQL
commits the data in its own transaction before the files are installed, so its journal can
point either way and the token decides. SQLite's restored database is a staged file
installed with the key files, so once its journal exists everything is ready and recovery
always rolls forward.

Verified by `server/admin/restore_overwrite_atomicity_test.go`: a failing load leaves the
live keys, rows and audit trail unchanged on both backends; a successful in-place restore
replaces both; a real restore process killed at each step boundary is resolved by
`--recover` as in the table above.
