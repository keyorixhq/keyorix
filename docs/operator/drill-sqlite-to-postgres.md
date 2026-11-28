# SQLite to PostgreSQL migration check

`scripts/migrate/sqlite-to-pg-check.sh` verifies the Standalone to Server growth path
with real binaries: it seeds a SQLite instance, moves it with `admin backup` and
`admin restore` (the supported path, see
[SELF_HOSTING.md](../SELF_HOSTING.md#moving-from-sqlite-to-postgres)) and then proves
the PostgreSQL copy. It shares its helpers with the other drills
(`scripts/drills/lib.sh`) and needs `curl`, `jq`, Go and `shasum`.

What it does and checks:

1. **Seed** a SQLite instance: projects, secrets with several versions, a soft-deleted
   and a suspended secret, a share, two users with MFA (password + TOTP), a group, a
   machine identity with a live and a revoked token, a dynamic-secret config (its
   admin DSN is encrypted at rest), break-glass history (one activation revoked), 2,000
   events of 30-day-old audit history that a real retention purge then removes (so a
   signed retention anchor exists), 10,000 more audit events, and a signed audit
   checkpoint exported to a directory standing in for off-host media.
2. **Migrate**: `admin backup` of the stopped SQLite instance, `admin restore` into a
   config that points at an empty PostgreSQL database.
3. **Every row present and equal**: row count and an order-independent SHA-256 of every
   row, per table, for every table (the script prints the count: `all 80 tables equal`
   at the time of writing). The checksum reads columns through `database/sql`
   and normalises the SQLite/PostgreSQL type differences, so it is independent of the
   backup format. Not compared, by design: `secret_nodes.cache_epoch` and four
   `system_metadata` keys the target writes itself (listed in `scripts/migrate/migratecheck/main.go`).
4. **The migrated instance works**: restore's own `verify-audit` says VALID; the chain
   also verifies against the checkpoint exported from SQLite before the move (no new
   genesis: the only new event is `admin.restore_completed`); the source's head row keeps
   its id and entry hash and `admin.restore_completed` carries it as `prev_hash`
   (`migratecheck audit-link`); the retention anchor is
   byte-identical; schema epoch equal on both sides and to the binary's; the server
   boots on PostgreSQL, the MFA admin and the second MFA user log in, every secret
   decrypts, versions, share, machine token, revoked token, suspended and deleted secret,
   break-glass history, group and dynamic-secret issue all work; the chain still verifies
   after the server has run.
5. **The other direction, PostgreSQL to SQLite**: `admin backup` of the migrated
   PostgreSQL instance (after the server ran on it) and `admin restore` into a config that
   points at an empty SQLite file, with the same checks as 3. and 4.: every table equal to the
   PostgreSQL instance, restore's `verify-audit` VALID, the chain also valid against the
   checkpoint exported before the first move, retention anchor byte-identical, and the server
   boots on SQLite with the same logins, secrets, share, tokens, history, group and
   dynamic-secret behaviour.
6. **Failure and rollback**: `admin restore` is killed with `kill -9` while migrating the
   target and while loading rows. It checks the SQLite file's SHA-256 is unchanged, the
   load left no partial rows, a plain re-run is refused (naming the interrupted restore),
   and the documented recovery works: `admin restore --recover` rolls back, the restore is
   run again (with `--overwrite-existing` when the refusal says the killed restore's empty
   schema is still there), and it ends with tables equal to the source and a VALID chain.
   Finally the SQLite source still starts.
7. **Refusals**: a restore into a PostgreSQL database that already holds a migration is
   refused (from an instance with no keys and from one that holds them) and leaves every
   table unchanged and no key file installed; a restore with a wrong master password is
   refused before the target is touched (no schema, no key file, no journal); a target that
   already holds its own key set is refused and keeps its `dek.key`, both when it also has a
   schema and when its database is empty (then the refusal is the key check alone, naming the
   existing key file); `--overwrite-existing` against an EMPTY target (no schema, no keys)
   completes like a plain restore, with equal tables and a VALID chain whose head is unchanged.

```sh
# three databases: A (migration target), B (target of the kill legs), C (any database the
# dynamic-secret config points at); each file holds one postgres://user:password@host:port/db
# URL (never on argv). A and B must be EMPTY.
MIGRATE_PG_DSN_FILE=a.txt MIGRATE_PG_DSN_FILE2=b.txt MIGRATE_PG_DSN_FILE3=c.txt \
  scripts/migrate/sqlite-to-pg-check.sh
```

The last line is `SQLITE -> POSTGRESQL MIGRATION CHECK PASSED`. Environment:
`MIGRATE_AUDIT_EVENTS` (default 10000), `DRILL_SERVER_BIN` / `DRILL_CLI_BIN` (default:
build this checkout), `DRILL_KEEP=1` (keep the work area).

What it does **not** cover: the container variants (`docker compose`, Helm) are pending a
run on the e2e VM; `--overwrite-existing` against a target that holds real data (documented,
never run: with `--replace-existing-data` it deletes the target's rows by design, so take a backup
of the target first); very large databases (this run is sized for tens of thousands of rows;
for millions of rows see [backup-restore-scale.md](backup-restore-scale.md) and
`scripts/migrate/scale-check.sh`).

## Verified matrix

Run of `scripts/migrate/sqlite-to-pg-check.sh` with the real `keyorix-server` and `keyorix`
binaries built from main at commit `f843ea087afcb7a6add38ee23925acbec08cc67f`, against a
local PostgreSQL (native, no containers); result `SQLITE -> POSTGRESQL MIGRATION CHECK PASSED`.

| Check | Result | Evidence |
|---|---|---|
| Row counts and checksums per table, SQLite vs PostgreSQL | all 80 tables equal | 28 non-empty tables, about 10,280 rows, 10,066 audit events |
| Secrets decrypt to the same plaintext (keys moved) | pass | 3 secrets, secret 1 at its latest of 3 versions, secret 4 with 2 versions |
| Users, roles, shares, group, MFA, break-glass, machine tokens | identical | counts and checksums equal; both MFA users log in; the revoked token is still rejected |
| Suspended and soft-deleted secrets | unchanged | value reads refused; the deleted one stays in the trash |
| Dynamic-secret config | pass | its encrypted admin DSN decrypts with the migrated keys and a credential is issued |
| `keyorix audit verify` on PostgreSQL | VALID | also VALID against the checkpoint exported before the move (no new genesis) |
| Audit chain continues | pass | head row keeps its entry hash; the first new event chains onto it; the chain still verifies after the server ran |
| Retention anchor and schema epoch | preserved | anchor byte-identical; schema epoch equal on both sides and to the binary's |
| Rollback | pass | the SQLite file is byte-identical after the restore and the source still starts and verifies |
| PostgreSQL back to SQLite | pass | all 80 tables equal; chain VALID against the first checkpoint; same logins and secrets |
| `kill -9` during restore (while migrating, while loading rows) | pass, 4 legs | no key file installed, no row committed; a re-run is refused until `--recover`; both recoveries finish with equal tables |
| Non-empty target | refused | tables unchanged, no key file installed |
| Wrong master password | refused | no schema, no key file, no journal |
| Target with its own keys and a schema | refused | its `dek.key` is unchanged |
| Target with its own keys, no schema | refused | non-zero exit, message names the existing key file; `dek.key` unchanged, no journal, no row |
| `--overwrite-existing` on an empty target | pass | tables equal the source; chain VALID, head unchanged, first new event chains onto it |
| `--overwrite-existing --replace-existing-data` on a target with data | documented, not run | deletes the target's rows by design |
| Container and Helm variants | pending e2e VM | not run |

## What to check after a move

1. `keyorix-server admin verify-audit` exits 0 and prints `Verdict: VALID` (give it the
   checkpoint key if the instance has been through a retention purge).
2. Events written after the move extend the chain: the newest source row keeps its entry hash and
   the next event's previous hash equals it. A fresh genesis means the chain was not carried over.
3. The same logins work (including TOTP), a migrated secret decrypts, and the suspended and
   soft-deleted secrets behave as before.
4. Keep the SQLite file untouched until then: pointing the config back at it is the rollback.

## Findings fixed by this check

- `admin restore` reported INDETERMINATE for any database that had been through a
  retention purge, because its automatic `verify-audit` was not given the checkpoint key.
- A restore changed SQL NULL in JSON columns (`secret_nodes.metadata`) to the text `null`.
- SELF_HOSTING.md said the archive contains its own `admin.backup_created` event; it is
  written to the source after the archive.

## Behaviour worth knowing

- The only write the migration makes to the SQLite source is the `admin.backup_created`
  event `admin backup` appends.
- TOTP anti-replay state moves with the data: the same code is refused on PostgreSQL
  inside its 30-second step. The script waits for a fresh code for that reason.
